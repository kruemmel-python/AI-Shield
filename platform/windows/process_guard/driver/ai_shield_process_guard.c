#include <ntifs.h>
#include <wdmsec.h>

#include "ai_shield_driver_protocol.h"
#include "ai_shield_event_queue.h"

static PDEVICE_OBJECT g_Device = NULL;
static EX_PUSH_LOCK g_PolicyLock;
static AI_SHIELD_DRIVER_POLICY g_Policy = {
    AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_POLICY), AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0};
static AI_SHIELD_DRIVER_STATUS g_Status = {
    AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_STATUS), AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0, 0};
static AI_SHIELD_EVENT_QUEUE g_EventQueue;
static PVOID g_ObRegistration = NULL;
static BOOLEAN g_ImageCallbackRegistered = FALSE;
static const GUID kDeviceClass = {0x7022431f, 0xf50e, 0x4e72, {0xb4, 0x90, 0x91, 0xa4, 0x93, 0x3a, 0x35, 0xd2}};
static const ACCESS_MASK kDangerousProcessAccess = 0x00000001U | 0x00000002U | 0x00000020U |
                                                   0x00000040U | 0x00000800U;

static AI_SHIELD_DRIVER_POLICY AiShieldReadPolicy(void) {
    AI_SHIELD_DRIVER_POLICY policy;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PolicyLock);
    policy = g_Policy;
    ExReleasePushLockShared(&g_PolicyLock);
    KeLeaveCriticalRegion();
    return policy;
}

static BOOLEAN AiShieldContainsQuarantine(const UNICODE_STRING* path) {
    static const UNICODE_STRING marker = RTL_CONSTANT_STRING(L"\\AI_Shield_Quarantine\\");
    USHORT offset;
    if (path == NULL || path->Buffer == NULL || path->Length < marker.Length) return FALSE;
    for (offset = 0; offset <= path->Length - marker.Length; offset += sizeof(WCHAR)) {
        UNICODE_STRING candidate;
        candidate.Buffer = path->Buffer + offset / sizeof(WCHAR);
        candidate.Length = marker.Length;
        candidate.MaximumLength = marker.Length;
        if (RtlEqualUnicodeString(&candidate, &marker, TRUE)) return TRUE;
    }
    return FALSE;
}

static BOOLEAN AiShieldContains(const UNICODE_STRING* value, PCWSTR markerBuffer) {
    UNICODE_STRING marker;
    USHORT offset;
    RtlInitUnicodeString(&marker, markerBuffer);
    if (value == NULL || value->Buffer == NULL || value->Length < marker.Length) return FALSE;
    for (offset = 0; offset <= value->Length - marker.Length; offset += sizeof(WCHAR)) {
        UNICODE_STRING candidate;
        candidate.Buffer = value->Buffer + offset / sizeof(WCHAR);
        candidate.Length = marker.Length;
        candidate.MaximumLength = marker.Length;
        if (RtlEqualUnicodeString(&candidate, &marker, TRUE)) return TRUE;
    }
    return FALSE;
}

static BOOLEAN AiShieldIsRiskyScriptCommand(const PPS_CREATE_NOTIFY_INFO createInfo) {
    BOOLEAN scriptHost;
    BOOLEAN riskyArgument;
    if (createInfo == NULL || createInfo->ImageFileName == NULL || createInfo->CommandLine == NULL) return FALSE;
    scriptHost = AiShieldContains(createInfo->ImageFileName, L"\\powershell.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\pwsh.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\mshta.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\wscript.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\cscript.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\regsvr32.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\rundll32.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\certutil.exe") ||
                 AiShieldContains(createInfo->ImageFileName, L"\\bitsadmin.exe");
    riskyArgument = AiShieldContains(createInfo->CommandLine, L" -enc ") ||
                    AiShieldContains(createInfo->CommandLine, L" -encodedcommand ") ||
                    AiShieldContains(createInfo->CommandLine, L"javascript:") ||
                    AiShieldContains(createInfo->CommandLine, L"http://") ||
                    AiShieldContains(createInfo->CommandLine, L"https://") ||
                    AiShieldContains(createInfo->CommandLine, L" -w hidden") ||
                    AiShieldContains(createInfo->CommandLine, L"downloadstring") ||
                    AiShieldContains(createInfo->CommandLine, L"invoke-webrequest") ||
                    AiShieldContains(createInfo->CommandLine, L"frombase64string") ||
                    AiShieldContains(createInfo->CommandLine, L" -urlcache") ||
                    AiShieldContains(createInfo->CommandLine, L" /transfer");
    return scriptHost && riskyArgument;
}

static BOOLEAN AiShieldIsDownloadedScriptLaunch(const PPS_CREATE_NOTIFY_INFO createInfo) {
    BOOLEAN interpreter;
    BOOLEAN downloadPath;
    if (createInfo == NULL || createInfo->ImageFileName == NULL || createInfo->CommandLine == NULL) return FALSE;
    interpreter = AiShieldContains(createInfo->ImageFileName, L"\\powershell.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\pwsh.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\cmd.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\wscript.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\cscript.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\mshta.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\bash.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\sh.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\wsl.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\python.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\python3.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\py.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\node.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\perl.exe") ||
                  AiShieldContains(createInfo->ImageFileName, L"\\ruby.exe");
    downloadPath = AiShieldContains(createInfo->CommandLine, L"\\Downloads\\") ||
                   AiShieldContains(createInfo->CommandLine, L"/Downloads/") ||
                   AiShieldContains(createInfo->CommandLine, L"\\Downloads/") ||
                   AiShieldContains(createInfo->CommandLine, L"/Downloads\\");
    return interpreter && downloadPath;
}

static BOOLEAN AiShieldIsOfficeChild(const PPS_CREATE_NOTIFY_INFO createInfo) {
    PEPROCESS parent = NULL;
    PUNICODE_STRING parentPath = NULL;
    BOOLEAN office = FALSE;
    BOOLEAN dangerousChild;
    if (createInfo == NULL || createInfo->ImageFileName == NULL || createInfo->ParentProcessId == NULL) return FALSE;
    dangerousChild = AiShieldContains(createInfo->ImageFileName, L"\\powershell.exe") ||
                     AiShieldContains(createInfo->ImageFileName, L"\\pwsh.exe") ||
                     AiShieldContains(createInfo->ImageFileName, L"\\cmd.exe") ||
                     AiShieldContains(createInfo->ImageFileName, L"\\wscript.exe") ||
                     AiShieldContains(createInfo->ImageFileName, L"\\cscript.exe") ||
                     AiShieldContains(createInfo->ImageFileName, L"\\mshta.exe") ||
                     AiShieldContains(createInfo->ImageFileName, L"\\rundll32.exe");
    if (!dangerousChild || !NT_SUCCESS(PsLookupProcessByProcessId(createInfo->ParentProcessId, &parent))) return FALSE;
    if (NT_SUCCESS(SeLocateProcessImageName(parent, &parentPath)) && parentPath != NULL) {
        office = AiShieldContains(parentPath, L"\\winword.exe") || AiShieldContains(parentPath, L"\\excel.exe") ||
                 AiShieldContains(parentPath, L"\\outlook.exe") || AiShieldContains(parentPath, L"\\powerpnt.exe");
        ExFreePool(parentPath);
    }
    ObDereferenceObject(parent);
    return office;
}

static BOOLEAN AiShieldIsCredentialOrPersistenceCommand(const PPS_CREATE_NOTIFY_INFO createInfo) {
    BOOLEAN credentialAccess;
    BOOLEAN persistence;
    if (createInfo == NULL || createInfo->ImageFileName == NULL || createInfo->CommandLine == NULL) return FALSE;
    credentialAccess = (AiShieldContains(createInfo->ImageFileName, L"\\procdump.exe") &&
                        AiShieldContains(createInfo->CommandLine, L"lsass")) ||
                       (AiShieldContains(createInfo->ImageFileName, L"\\rundll32.exe") &&
                        AiShieldContains(createInfo->CommandLine, L"comsvcs.dll") &&
                        AiShieldContains(createInfo->CommandLine, L"minidump")) ||
                       (AiShieldContains(createInfo->ImageFileName, L"\\reg.exe") &&
                        (AiShieldContains(createInfo->CommandLine, L"sam") ||
                         AiShieldContains(createInfo->CommandLine, L"security")) &&
                        AiShieldContains(createInfo->CommandLine, L" save "));
    persistence = (AiShieldContains(createInfo->ImageFileName, L"\\schtasks.exe") &&
                   AiShieldContains(createInfo->CommandLine, L" /create")) ||
                  (AiShieldContains(createInfo->ImageFileName, L"\\sc.exe") &&
                   AiShieldContains(createInfo->CommandLine, L" create ")) ||
                  (AiShieldContains(createInfo->ImageFileName, L"\\reg.exe") &&
                   AiShieldContains(createInfo->CommandLine, L"\\currentversion\\run") &&
                   AiShieldContains(createInfo->CommandLine, L" add ")) ||
                  (AiShieldContains(createInfo->ImageFileName, L"\\wmic.exe") &&
                   AiShieldContains(createInfo->CommandLine, L"process call create"));
    return credentialAccess || persistence;
}

static ULONGLONG AiShieldPathId(const UNICODE_STRING* path) {
    ULONGLONG hash = 1469598103934665603ULL;
    USHORT index;
    if (path == NULL || path->Buffer == NULL) return 0;
    for (index = 0; index < path->Length / sizeof(WCHAR); ++index) {
        hash ^= (ULONGLONG)RtlUpcaseUnicodeChar(path->Buffer[index]);
        hash *= 1099511628211ULL;
    }
    return hash;
}

static BOOLEAN AiShieldIsExternalImagePath(const UNICODE_STRING* path) {
    return AiShieldContains(path, L"\\Downloads\\") ||
           AiShieldContains(path, L"\\AppData\\Local\\Temp\\") ||
           AiShieldContains(path, L"\\AI_Shield_Quarantine\\") ||
           AiShieldContains(path, L"\\ProgramData\\AIShield\\quarantine\\");
}

static void AiShieldImageNotify(PUNICODE_STRING fullImageName, HANDLE processId, PIMAGE_INFO imageInfo) {
    AI_SHIELD_DRIVER_POLICY policy;
    AI_SHIELD_DRIVER_EVENT event = {0};
    UNREFERENCED_PARAMETER(imageInfo);
    if (processId == NULL || fullImageName == NULL) return;
    policy = AiShieldReadPolicy();
    if (!AiShieldIsExternalImagePath(fullImageName) &&
        (policy.ExemptProcessId == 0U || (ULONG_PTR)processId != policy.ExemptProcessId)) return;
    event.Sensor = AI_SHIELD_SENSOR_PROCESS;
    event.Kind = AI_SHIELD_EVENT_IMAGE_LOAD;
    event.Timestamp100ns = KeQueryInterruptTime();
    event.ProcessId = (ULONGLONG)(ULONG_PTR)processId;
    event.SubjectId = AiShieldPathId(fullImageName);
    event.Decision = STATUS_SUCCESS;
    if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
}

static OB_PREOP_CALLBACK_STATUS AiShieldObjectPreOperation(PVOID registrationContext,
                                                            POB_PRE_OPERATION_INFORMATION information) {
    AI_SHIELD_DRIVER_POLICY policy = AiShieldReadPolicy();
    ACCESS_MASK* desiredAccess = NULL;
    ACCESS_MASK originalAccess;
    HANDLE targetProcessId;
    HANDLE callerProcessId = PsGetCurrentProcessId();
    AI_SHIELD_DRIVER_EVENT event = {0};
    UNREFERENCED_PARAMETER(registrationContext);
    if (policy.Mode != AI_SHIELD_POLICY_ENFORCE || policy.ExemptProcessId == 0U ||
        information->ObjectType != *PsProcessType || information->KernelHandle) return OB_PREOP_SUCCESS;
    targetProcessId = PsGetProcessId((PEPROCESS)information->Object);
    if ((ULONG_PTR)targetProcessId != policy.ExemptProcessId || targetProcessId == callerProcessId ||
        (ULONG_PTR)callerProcessId == 4U) return OB_PREOP_SUCCESS;
    if (information->Operation == OB_OPERATION_HANDLE_CREATE)
        desiredAccess = &information->Parameters->CreateHandleInformation.DesiredAccess;
    else if (information->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        desiredAccess = &information->Parameters->DuplicateHandleInformation.DesiredAccess;
    if (desiredAccess == NULL) return OB_PREOP_SUCCESS;
    originalAccess = *desiredAccess;
    *desiredAccess &= ~kDangerousProcessAccess;
    if (*desiredAccess == originalAccess) return OB_PREOP_SUCCESS;
    event.Sensor = AI_SHIELD_SENSOR_PROCESS;
    event.Kind = AI_SHIELD_EVENT_HANDLE_FILTER;
    event.Timestamp100ns = KeQueryInterruptTime();
    event.ProcessId = (ULONGLONG)(ULONG_PTR)callerProcessId;
    event.SubjectId = (ULONGLONG)(ULONG_PTR)targetProcessId;
    event.Decision = originalAccess ^ *desiredAccess;
    event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
    InterlockedIncrement64(&g_Status.Blocked);
    if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
    return OB_PREOP_SUCCESS;
}

static NTSTATUS AiShieldRegisterObjectCallbacks(void) {
    static UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370121");
    OB_OPERATION_REGISTRATION operation = {0};
    OB_CALLBACK_REGISTRATION registration = {0};
    operation.ObjectType = PsProcessType;
    operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation.PreOperation = AiShieldObjectPreOperation;
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.Altitude = altitude;
    registration.OperationRegistration = &operation;
    return ObRegisterCallbacks(&registration, &g_ObRegistration);
}

static void AiShieldProcessNotify(PEPROCESS process, HANDLE processId, PPS_CREATE_NOTIFY_INFO createInfo) {
    AI_SHIELD_DRIVER_POLICY policy;
    AI_SHIELD_DRIVER_EVENT event = {0};
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(processId);
    if (createInfo == NULL) return;
    InterlockedIncrement64(&g_Status.Observed);
    event.Sensor = AI_SHIELD_SENSOR_PROCESS;
    event.Kind = AI_SHIELD_EVENT_PROCESS_CREATE;
    event.Timestamp100ns = KeQueryInterruptTime();
    event.ProcessId = (ULONGLONG)(ULONG_PTR)processId;
    event.SubjectId = AiShieldPathId(createInfo->ImageFileName);
    event.Reserved = (ULONG)(ULONG_PTR)createInfo->ParentProcessId;
    policy = AiShieldReadPolicy();
    {
        BOOLEAN block = FALSE;
        if ((policy.Flags & AI_SHIELD_POLICY_BLOCK_QUARANTINE_EXECUTION) != 0U &&
            AiShieldContainsQuarantine(createInfo->ImageFileName)) block = TRUE;
        if ((policy.Flags & AI_SHIELD_POLICY_BLOCK_USER_TEMP_EXECUTION) != 0U &&
            AiShieldContains(createInfo->ImageFileName, L"\\AppData\\Local\\Temp\\")) block = TRUE;
        if ((policy.Flags & AI_SHIELD_POLICY_BLOCK_DOWNLOAD_EXECUTION) != 0U &&
            (AiShieldContains(createInfo->ImageFileName, L"\\Downloads\\") ||
             AiShieldIsDownloadedScriptLaunch(createInfo))) {
            block = TRUE;
            event.Flags |= AI_SHIELD_EVENT_FLAG_RISKY_COMMAND;
        }
        if ((policy.Flags & AI_SHIELD_POLICY_BLOCK_RISKY_SCRIPT_COMMAND) != 0U &&
            (AiShieldIsRiskyScriptCommand(createInfo) || AiShieldIsCredentialOrPersistenceCommand(createInfo))) {
            block = TRUE;
            event.Flags |= AI_SHIELD_EVENT_FLAG_RISKY_COMMAND;
        }
        if ((policy.Flags & AI_SHIELD_POLICY_BLOCK_OFFICE_CHILD_PROCESS) != 0U &&
            AiShieldIsOfficeChild(createInfo)) {
            block = TRUE;
            event.Flags |= AI_SHIELD_EVENT_FLAG_OFFICE_CHILD;
        }
        if (block && policy.Mode == AI_SHIELD_POLICY_ENFORCE) {
        createInfo->CreationStatus = STATUS_ACCESS_DENIED;
        InterlockedIncrement64(&g_Status.Blocked);
        event.Decision = (ULONG)STATUS_ACCESS_DENIED;
        event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return;
        }
    }
    InterlockedIncrement64(&g_Status.Allowed);
    event.Decision = STATUS_SUCCESS;
    if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
}

static NTSTATUS AiShieldCreateClose(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS AiShieldDeviceControl(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes = 0;
    UNREFERENCED_PARAMETER(device);
    if (stack->Parameters.DeviceIoControl.IoControlCode == AI_SHIELD_IOCTL_GET_STATUS &&
        stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(g_Status)) {
        AI_SHIELD_DRIVER_POLICY policy = AiShieldReadPolicy();
        g_Status.Mode = policy.Mode;
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &g_Status, sizeof(g_Status));
        bytes = sizeof(g_Status);
        status = STATUS_SUCCESS;
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AI_SHIELD_IOCTL_SET_POLICY &&
               stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(g_Policy)) {
        AI_SHIELD_DRIVER_POLICY* policy = (AI_SHIELD_DRIVER_POLICY*)irp->AssociatedIrp.SystemBuffer;
        if (policy->Version == AI_SHIELD_PROTOCOL_VERSION && policy->Size == sizeof(g_Policy) &&
            policy->Mode <= AI_SHIELD_POLICY_ENFORCE &&
            (policy->Flags & ~AI_SHIELD_POLICY_ALL_FLAGS) == 0U) {
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&g_PolicyLock);
            g_Policy = *policy;
            ExReleasePushLockExclusive(&g_PolicyLock);
            KeLeaveCriticalRegion();
            status = STATUS_SUCCESS;
        } else status = STATUS_INVALID_PARAMETER;
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AI_SHIELD_IOCTL_GET_EVENT &&
               stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(AI_SHIELD_DRIVER_EVENT)) {
        AI_SHIELD_DRIVER_EVENT event;
        if (AiShieldEventQueuePop(&g_EventQueue, &event)) {
            RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &event, sizeof(event));
            bytes = sizeof(event);
            status = STATUS_SUCCESS;
        } else status = STATUS_NO_MORE_ENTRIES;
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static void AiShieldUnload(PDRIVER_OBJECT driver) {
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\AIShieldProcessGuard");
    UNREFERENCED_PARAMETER(driver);
    PsSetCreateProcessNotifyRoutineEx(AiShieldProcessNotify, TRUE);
    if (g_ImageCallbackRegistered) {
        PsRemoveLoadImageNotifyRoutine(AiShieldImageNotify);
        g_ImageCallbackRegistered = FALSE;
    }
    if (g_ObRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObRegistration);
        g_ObRegistration = NULL;
    }
    IoDeleteSymbolicLink(&link);
    if (g_Device != NULL) { IoDeleteDevice(g_Device); g_Device = NULL; }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\AIShieldProcessGuard");
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\AIShieldProcessGuard");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);
    ExInitializePushLock(&g_PolicyLock);
    AiShieldEventQueueInitialize(&g_EventQueue);
    driver->DriverUnload = AiShieldUnload;
    driver->MajorFunction[IRP_MJ_CREATE] = AiShieldCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = AiShieldCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AiShieldDeviceControl;
    status = IoCreateDeviceSecure(driver, 0, &deviceName, AI_SHIELD_DEVICE_TYPE,
                                  FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, &kDeviceClass, &g_Device);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&link, &deviceName);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return status; }
    status = PsSetCreateProcessNotifyRoutineEx(AiShieldProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return status; }
    status = PsSetLoadImageNotifyRoutine(AiShieldImageNotify);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return status; }
    g_ImageCallbackRegistered = TRUE;
    status = AiShieldRegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return status; }
    g_Device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
