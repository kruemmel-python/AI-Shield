#include <fltKernel.h>
#include <wdmsec.h>

#include "ai_shield_driver_protocol.h"
#include "ai_shield_event_queue.h"

static PFLT_FILTER g_Filter = NULL;
static PDEVICE_OBJECT g_ControlDevice = NULL;
static EX_PUSH_LOCK g_PolicyLock;
static AI_SHIELD_DRIVER_POLICY g_Policy = {
    AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_POLICY), AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0};
static AI_SHIELD_DRIVER_STATUS g_Status = {
    AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_STATUS), AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0, 0};
static AI_SHIELD_EVENT_QUEUE g_EventQueue;
static const GUID kDeviceClass = {0x23c2c69e, 0xc461, 0x47b8, {0xb0, 0xdd, 0xb0, 0xd4, 0xad, 0x94, 0x42, 0xcf}};

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

static BOOLEAN AiShieldIsProtectedStorage(const UNICODE_STRING* path) {
    static const UNICODE_STRING marker = RTL_CONSTANT_STRING(L"\\ProgramData\\AIShield\\");
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

static BOOLEAN AiShieldIsExternalWorkPath(const UNICODE_STRING* path) {
    static const UNICODE_STRING downloads = RTL_CONSTANT_STRING(L"\\Downloads\\");
    static const UNICODE_STRING desktop = RTL_CONSTANT_STRING(L"\\Desktop\\");
    static const UNICODE_STRING documents = RTL_CONSTANT_STRING(L"\\Documents\\");
    static const UNICODE_STRING pictures = RTL_CONSTANT_STRING(L"\\Pictures\\");
    static const UNICODE_STRING music = RTL_CONSTANT_STRING(L"\\Music\\");
    static const UNICODE_STRING videos = RTL_CONSTANT_STRING(L"\\Videos\\");
    static const UNICODE_STRING temp = RTL_CONSTANT_STRING(L"\\AppData\\Local\\Temp\\");
    static const UNICODE_STRING quarantine = RTL_CONSTANT_STRING(L"\\AI_Shield_Quarantine\\");
    const UNICODE_STRING* markers[] = {
        &downloads, &desktop, &documents, &pictures, &music, &videos, &temp, &quarantine};
    ULONG markerIndex;
    if (path == NULL || path->Buffer == NULL) return FALSE;
    for (markerIndex = 0; markerIndex < RTL_NUMBER_OF(markers); ++markerIndex) {
        USHORT offset;
        const UNICODE_STRING* marker = markers[markerIndex];
        if (path->Length < marker->Length) continue;
        for (offset = 0; offset <= path->Length - marker->Length; offset += sizeof(WCHAR)) {
            UNICODE_STRING candidate;
            candidate.Buffer = path->Buffer + offset / sizeof(WCHAR);
            candidate.Length = marker->Length;
            candidate.MaximumLength = marker->Length;
            if (RtlEqualUnicodeString(&candidate, marker, TRUE)) return TRUE;
        }
    }
    return FALSE;
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

static void AiShieldSetFileIdentity(PCFLT_RELATED_OBJECTS objects, AI_SHIELD_DRIVER_EVENT* event) {
    FILE_INTERNAL_INFORMATION internalInformation;
    struct {
        FILE_FS_VOLUME_INFORMATION Information;
        WCHAR LabelBuffer[260];
    } volumeInformation;
    ULONG returned = 0;
    IO_STATUS_BLOCK volumeStatus;
    if (objects == NULL || objects->Instance == NULL || objects->FileObject == NULL || objects->Volume == NULL)
        return;
    RtlZeroMemory(&internalInformation, sizeof(internalInformation));
    if (!NT_SUCCESS(FltQueryInformationFile(objects->Instance, objects->FileObject, &internalInformation,
                                             sizeof(internalInformation), FileInternalInformation, &returned)))
        return;
    RtlZeroMemory(&volumeInformation, sizeof(volumeInformation));
    RtlZeroMemory(&volumeStatus, sizeof(volumeStatus));
    if (!NT_SUCCESS(FltQueryVolumeInformation(objects->Instance, &volumeStatus, &volumeInformation,
                                               sizeof(volumeInformation), FileFsVolumeInformation)))
        return;
    event->SubjectId = (ULONGLONG)internalInformation.IndexNumber.QuadPart;
    event->Reserved = volumeInformation.Information.VolumeSerialNumber;
}

static BOOLEAN AiShieldBuildFileEvent(PFLT_CALLBACK_DATA data, ULONG kind, AI_SHIELD_DRIVER_EVENT* event,
                                      BOOLEAN externalOnly, BOOLEAN* quarantine, PCFLT_RELATED_OBJECTS objects) {
    PFLT_FILE_NAME_INFORMATION name = NULL;
    BOOLEAN accepted = FALSE;
    RtlZeroMemory(event, sizeof(*event));
    event->Sensor = AI_SHIELD_SENSOR_MINIFILTER;
    event->Kind = kind;
    event->Timestamp100ns = KeQueryInterruptTime();
    event->ProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (NT_SUCCESS(FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name))) {
        if (!AiShieldIsProtectedStorage(&name->Name) && (!externalOnly || AiShieldIsExternalWorkPath(&name->Name))) {
            event->SubjectId = AiShieldPathId(&name->Name);
            if (quarantine != NULL) *quarantine = AiShieldContainsQuarantine(&name->Name);
            accepted = TRUE;
        }
        FltReleaseFileNameInformation(name);
    }
    if (accepted) AiShieldSetFileIdentity(objects, event);
    return accepted;
}

static FLT_PREOP_CALLBACK_STATUS AiShieldPreWrite(PFLT_CALLBACK_DATA data,
                                                   PCFLT_RELATED_OBJECTS objects,
                                                   PVOID* completionContext) {
    AI_SHIELD_DRIVER_EVENT event;
    UNREFERENCED_PARAMETER(completionContext);
    if (AiShieldBuildFileEvent(data, AI_SHIELD_EVENT_FILE_WRITE, &event, TRUE, NULL, objects)) {
        event.Decision = STATUS_SUCCESS;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS AiShieldPreSetInformation(PFLT_CALLBACK_DATA data,
                                                            PCFLT_RELATED_OBJECTS objects,
                                                            PVOID* completionContext) {
    AI_SHIELD_DRIVER_EVENT event;
    FILE_INFORMATION_CLASS informationClass = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    UNREFERENCED_PARAMETER(completionContext);
    if ((informationClass == FileRenameInformation || informationClass == FileRenameInformationEx) &&
        AiShieldBuildFileEvent(data, AI_SHIELD_EVENT_FILE_RENAME, &event, TRUE, NULL, objects)) {
        event.Decision = STATUS_SUCCESS;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS AiShieldPreAcquireSection(PFLT_CALLBACK_DATA data,
                                                            PCFLT_RELATED_OBJECTS objects,
                                                            PVOID* completionContext) {
    AI_SHIELD_DRIVER_POLICY policy = AiShieldReadPolicy();
    AI_SHIELD_DRIVER_EVENT event;
    BOOLEAN quarantine = FALSE;
    UNREFERENCED_PARAMETER(completionContext);
    if (!AiShieldBuildFileEvent(data, AI_SHIELD_EVENT_IMAGE_SECTION, &event, FALSE, &quarantine, objects))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (quarantine && policy.Mode == AI_SHIELD_POLICY_ENFORCE &&
        (policy.Flags & AI_SHIELD_POLICY_BLOCK_QUARANTINE_EXECUTION) != 0U) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        event.Decision = (ULONG)STATUS_ACCESS_DENIED;
        event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
        InterlockedIncrement64(&g_Status.Blocked);
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return FLT_PREOP_COMPLETE;
    }
    event.Decision = STATUS_SUCCESS;
    if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS AiShieldPreCreate(PFLT_CALLBACK_DATA data,
                                                    PCFLT_RELATED_OBJECTS objects,
                                                    PVOID* completionContext) {
    AI_SHIELD_DRIVER_POLICY policy = AiShieldReadPolicy();
    AI_SHIELD_DRIVER_EVENT event = {0};
    ACCESS_MASK desiredAccess = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    PFLT_FILE_NAME_INFORMATION name = NULL;
    BOOLEAN quarantine = FALSE;
    BOOLEAN executionRequest = (desiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) != 0U;
    UNREFERENCED_PARAMETER(objects);
    UNREFERENCED_PARAMETER(completionContext);
    event.Sensor = AI_SHIELD_SENSOR_MINIFILTER;
    event.Kind = AI_SHIELD_EVENT_FILE_OPEN;
    event.Timestamp100ns = KeQueryInterruptTime();
    event.ProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (NT_SUCCESS(FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name))) {
        if (AiShieldIsProtectedStorage(&name->Name)) {
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if (executionRequest) quarantine = AiShieldContainsQuarantine(&name->Name);
        event.SubjectId = AiShieldPathId(&name->Name);
        FltReleaseFileNameInformation(name);
    }
    InterlockedIncrement64(&g_Status.Observed);
    if (quarantine && policy.Mode == AI_SHIELD_POLICY_ENFORCE &&
        (policy.Flags & AI_SHIELD_POLICY_BLOCK_QUARANTINE_EXECUTION) != 0U) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        InterlockedIncrement64(&g_Status.Blocked);
        event.Decision = (ULONG)STATUS_ACCESS_DENIED;
        event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return FLT_PREOP_COMPLETE;
    }
    InterlockedIncrement64(&g_Status.Allowed);
    if (!executionRequest) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    event.Decision = STATUS_SUCCESS;
    if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
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

static void AiShieldDeleteControlDevice(void) {
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\AIShieldMiniFilter");
    IoDeleteSymbolicLink(&link);
    if (g_ControlDevice != NULL) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }
}

static NTSTATUS AiShieldUnload(FLT_FILTER_UNLOAD_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    if (g_Filter != NULL) {
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
    }
    AiShieldDeleteControlDevice();
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION kCallbacks[] = {
    {IRP_MJ_CREATE, 0, AiShieldPreCreate, NULL},
    {IRP_MJ_WRITE, 0, AiShieldPreWrite, NULL},
    {IRP_MJ_SET_INFORMATION, 0, AiShieldPreSetInformation, NULL},
    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, AiShieldPreAcquireSection, NULL},
    {IRP_MJ_OPERATION_END}};
static const FLT_REGISTRATION kRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, kCallbacks, AiShieldUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\AIShieldMiniFilter");
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\AIShieldMiniFilter");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);
    ExInitializePushLock(&g_PolicyLock);
    AiShieldEventQueueInitialize(&g_EventQueue);
    driver->MajorFunction[IRP_MJ_CREATE] = AiShieldCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = AiShieldCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AiShieldDeviceControl;
    status = IoCreateDeviceSecure(driver, 0, &deviceName, AI_SHIELD_DEVICE_TYPE,
                                  FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, &kDeviceClass,
                                  &g_ControlDevice);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&link, &deviceName);
    if (!NT_SUCCESS(status)) { AiShieldDeleteControlDevice(); return status; }
    status = FltRegisterFilter(driver, &kRegistration, &g_Filter);
    if (!NT_SUCCESS(status)) { AiShieldDeleteControlDevice(); return status; }
    status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
        AiShieldDeleteControlDevice();
        return status;
    }
    g_ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
