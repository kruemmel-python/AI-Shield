#define NDIS_SUPPORT_NDIS6 1
#include <ntifs.h>
#include <netioddk.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <wdmsec.h>

#include "ai_shield_driver_protocol.h"
#include "ai_shield_event_queue.h"

static const GUID kProvider = {0x8bd45e31, 0xe31a, 0x4ad5, {0x91, 0x27, 0x10, 0x94, 0x21, 0x82, 0x75, 0x10}};
static const GUID kSublayer = {0x9510ed91, 0x4eaf, 0x4732, {0xa8, 0x24, 0x77, 0x4f, 0x20, 0x93, 0x48, 0x66}};
static const GUID kConnectCallout = {0xc1287bc9, 0x706d, 0x43d3, {0x8a, 0x24, 0x8e, 0x6a, 0xac, 0x91, 0x00, 0x11}};
static const GUID kAcceptCallout = {0xa5c1b27d, 0x97f7, 0x47fd, {0x90, 0x7c, 0x6c, 0x82, 0x39, 0x18, 0x11, 0x72}};
static const GUID kRedirectCallout = {0x154d48e4, 0x272e, 0x41fb, {0x9a, 0x75, 0x1d, 0x4c, 0x44, 0x63, 0x72, 0x99}};
static const GUID kConnectCalloutV6 = {0x3869ce18, 0xee65, 0x467f, {0xaa, 0x81, 0xc7, 0x5e, 0xc5, 0x72, 0x9f, 0x31}};
static const GUID kAcceptCalloutV6 = {0xd744fc22, 0x2e85, 0x44da, {0xb8, 0xad, 0x45, 0x6e, 0x96, 0xd6, 0xa8, 0xe7}};
static const GUID kRedirectCalloutV6 = {0x7a325368, 0x4247, 0x413c, {0xb4, 0xf1, 0xea, 0x69, 0xe3, 0xf5, 0x20, 0x55}};
static const GUID kDeviceClass = {0xf752f8b1, 0xa67d, 0x43a5, {0x88, 0xcc, 0xcf, 0x46, 0xb4, 0x48, 0x59, 0x84}};

static PDEVICE_OBJECT g_Device = NULL;
static HANDLE g_Engine = NULL;
static UINT32 g_ConnectId = 0;
static UINT32 g_AcceptId = 0;
static UINT32 g_RedirectId = 0;
static UINT32 g_ConnectIdV6 = 0;
static UINT32 g_AcceptIdV6 = 0;
static UINT32 g_RedirectIdV6 = 0;
static HANDLE g_RedirectHandle = NULL;
static EX_PUSH_LOCK g_PolicyLock;
static AI_SHIELD_DRIVER_POLICY g_Policy = {
    AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_POLICY), AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0};
static AI_SHIELD_DRIVER_STATUS g_Status = {
    AI_SHIELD_PROTOCOL_VERSION, sizeof(AI_SHIELD_DRIVER_STATUS), AI_SHIELD_POLICY_AUDIT, 0, 0, 0, 0, 0, 0};
static AI_SHIELD_EVENT_QUEUE g_EventQueue;
static PEPROCESS volatile g_BrokerProcess = NULL;
static PEPROCESS volatile g_IsolatedProcess = NULL;

#define AI_SHIELD_STAGE_STATUS(stage) ((NTSTATUS)(0xC0E10000U | (stage)))

static BOOLEAN AiShieldCurrentProcessIs(PEPROCESS volatile* expected) {
    return (PEPROCESS)InterlockedCompareExchangePointer((PVOID volatile*)expected, NULL, NULL) ==
           PsGetCurrentProcess();
}

static VOID AiShieldReplaceProcess(PEPROCESS volatile* destination, PEPROCESS process) {
    PEPROCESS previous;
    ObReferenceObject(process);
    previous = (PEPROCESS)InterlockedExchangePointer((PVOID volatile*)destination, process);
    if (previous != NULL) ObDereferenceObject(previous);
}

static AI_SHIELD_DRIVER_POLICY AiShieldReadPolicy(void) {
    AI_SHIELD_DRIVER_POLICY policy;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PolicyLock);
    policy = g_Policy;
    ExReleasePushLockShared(&g_PolicyLock);
    KeLeaveCriticalRegion();
    return policy;
}

static BOOLEAN AiShieldProcessPathContains(const FWPS_INCOMING_METADATA_VALUES0* metadata, PCWSTR markerBuffer) {
    UNICODE_STRING path;
    UNICODE_STRING marker;
    USHORT offset;
    if ((metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) == 0U ||
        metadata->processPath == NULL || metadata->processPath->data == NULL ||
        metadata->processPath->size > MAXUSHORT) return FALSE;
    path.Buffer = (PWSTR)metadata->processPath->data;
    path.Length = (USHORT)metadata->processPath->size;
    path.MaximumLength = path.Length;
    RtlInitUnicodeString(&marker, markerBuffer);
    if (path.Length < marker.Length) return FALSE;
    for (offset = 0; offset <= path.Length - marker.Length; offset += sizeof(WCHAR)) {
        UNICODE_STRING candidate;
        candidate.Buffer = path.Buffer + offset / sizeof(WCHAR);
        candidate.Length = marker.Length;
        candidate.MaximumLength = marker.Length;
        if (RtlEqualUnicodeString(&candidate, &marker, TRUE)) return TRUE;
    }
    return FALSE;
}

static BOOLEAN AiShieldProcessPathEndsWith(const FWPS_INCOMING_METADATA_VALUES0* metadata, PCWSTR suffixBuffer) {
    UNICODE_STRING path;
    UNICODE_STRING suffix;
    UNICODE_STRING candidate;
    if ((metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) == 0U ||
        metadata->processPath == NULL || metadata->processPath->data == NULL ||
        metadata->processPath->size > MAXUSHORT) return FALSE;
    path.Buffer = (PWSTR)metadata->processPath->data;
    path.Length = (USHORT)metadata->processPath->size;
    path.MaximumLength = path.Length;
    RtlInitUnicodeString(&suffix, suffixBuffer);
    if (path.Length < suffix.Length) return FALSE;
    candidate.Buffer = path.Buffer + (path.Length - suffix.Length) / sizeof(WCHAR);
    candidate.Length = suffix.Length;
    candidate.MaximumLength = suffix.Length;
    return RtlEqualUnicodeString(&candidate, &suffix, TRUE);
}

static BOOLEAN AiShieldIsBrowser(const FWPS_INCOMING_METADATA_VALUES0* metadata) {
    return AiShieldProcessPathContains(metadata, L"\\chrome.exe") ||
           AiShieldProcessPathContains(metadata, L"\\msedge.exe") ||
           AiShieldProcessPathContains(metadata, L"\\firefox.exe") ||
           AiShieldProcessPathContains(metadata, L"\\brave.exe") ||
           AiShieldProcessPathContains(metadata, L"\\opera.exe");
}

static BOOLEAN AiShieldIsFileScanner(const FWPS_INCOMING_METADATA_VALUES0* metadata) {
    return AiShieldProcessPathEndsWith(metadata,
        L"\\program files\\aishield\\bin\\ai_shield_file_scanner.exe");
}

static BOOLEAN AiShieldIsWebPort(UINT16 port) {
    return port == 53U || port == 80U || port == 443U || port == 853U;
}

static BOOLEAN AiShieldIsWormEgressPort(UINT16 port) {
    return port == 135U || (port >= 137U && port <= 139U) || port == 445U || port == 3389U;
}

static ULONGLONG AiShieldAddressId(const UINT8* bytes, SIZE_T length) {
    ULONGLONG hash = 1469598103934665603ULL;
    SIZE_T index;
    if (bytes == NULL) return 0U;
    for (index = 0; index < length; ++index) { hash ^= bytes[index]; hash *= 1099511628211ULL; }
    return hash;
}

static void NTAPI AiShieldAuthorizeClassify(const FWPS_INCOMING_VALUES0* values,
                                      const FWPS_INCOMING_METADATA_VALUES0* metadata,
                                      void* layerData,
                                      const void* classifyContext,
                                      const FWPS_FILTER1* filter,
                                      UINT64 flowContext,
                                      FWPS_CLASSIFY_OUT0* classifyOut) {
    AI_SHIELD_DRIVER_POLICY policy = AiShieldReadPolicy();
    AI_SHIELD_DRIVER_EVENT event = {0};
    UINT16 port = 0;
    BOOLEAN outbound = FALSE;
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);
    InterlockedIncrement64(&g_Status.Observed);
    event.Sensor = AI_SHIELD_SENSOR_WFP;
    event.Timestamp100ns = KeQueryInterruptTime();
    if ((metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0U)
        event.ProcessId = metadata->processId;
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0U) {
        InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return;
    }
    if (values->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4) {
        event.Kind = AI_SHIELD_EVENT_ACCEPT;
        port = values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
        event.LocalPort = port;
        event.Reserved = values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
        event.SubjectId = values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
    } else if (values->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6) {
        event.Kind = AI_SHIELD_EVENT_ACCEPT;
        event.Flags |= AI_SHIELD_EVENT_FLAG_IPV6;
        port = values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
        event.LocalPort = port;
        event.Reserved = values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
        event.SubjectId = AiShieldAddressId(
            values->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16,
            16U);
    } else if (values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        event.Kind = AI_SHIELD_EVENT_CONNECT;
        port = values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        event.RemotePort = port;
        event.Reserved = values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
        event.SubjectId = values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        outbound = TRUE;
    } else if (values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        event.Kind = AI_SHIELD_EVENT_CONNECT;
        event.Flags |= AI_SHIELD_EVENT_FLAG_IPV6;
        port = values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
        event.RemotePort = port;
        event.Reserved = values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
        event.SubjectId = AiShieldAddressId(
            values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16,
            16U);
        outbound = TRUE;
    }
    if (AiShieldCurrentProcessIs(&g_IsolatedProcess) || AiShieldIsFileScanner(metadata)) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_Status.Blocked);
        event.Decision = FWP_ACTION_BLOCK;
        event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return;
    }
    if (policy.Mode == AI_SHIELD_POLICY_ENFORCE && outbound &&
        (((policy.Flags & AI_SHIELD_POLICY_SYSTEM_NETWORK_GUARD) != 0U && AiShieldIsWormEgressPort(port)) ||
         ((policy.Flags & AI_SHIELD_POLICY_BLOCK_BROWSER_NON_WEB) != 0U && AiShieldIsBrowser(metadata) &&
          !AiShieldIsWebPort(port)))) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_Status.Blocked);
        event.Decision = FWP_ACTION_BLOCK;
        event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return;
    }
    if (policy.Mode == AI_SHIELD_POLICY_ENFORCE && !outbound &&
        (policy.Flags & AI_SHIELD_POLICY_BLOCK_UNSOLICITED_INBOUND) != 0U &&
        (policy.ProxyPort == 0U || port != (UINT16)policy.ProxyPort)) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_Status.Blocked);
        event.Decision = FWP_ACTION_BLOCK;
        event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return;
    }
    if (policy.Mode == AI_SHIELD_POLICY_ENFORCE && filter->context == 1U &&
        policy.BlockInboundPort != 0U && port == (UINT16)policy.BlockInboundPort) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        InterlockedIncrement64(&g_Status.Blocked);
        event.Decision = FWP_ACTION_BLOCK;
        event.Flags |= AI_SHIELD_EVENT_FLAG_BLOCKED;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
        return;
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;
    InterlockedIncrement64(&g_Status.Allowed);
    event.Decision = FWP_ACTION_PERMIT;
    if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
}

static void NTAPI AiShieldRedirectClassify(const FWPS_INCOMING_VALUES0* values,
                                     const FWPS_INCOMING_METADATA_VALUES0* metadata,
                                     void* layerData,
                                     const void* classifyContext,
                                     const FWPS_FILTER1* filter,
                                     UINT64 flowContext,
                                     FWPS_CLASSIFY_OUT0* classifyOut) {
    AI_SHIELD_DRIVER_POLICY policy = AiShieldReadPolicy();
    AI_SHIELD_DRIVER_EVENT event = {0};
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST0* request = NULL;
    UINT16 remotePort;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(metadata);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);
    InterlockedIncrement64(&g_Status.Observed);
    event.Sensor = AI_SHIELD_SENSOR_WFP;
    event.Kind = AI_SHIELD_EVENT_REDIRECT;
    event.Timestamp100ns = KeQueryInterruptTime();
    if ((metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0U)
        event.ProcessId = metadata->processId;
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0U) return;
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (policy.Mode != AI_SHIELD_POLICY_ENFORCE || policy.RedirectOutboundPort == 0U ||
        policy.ProxyPort == 0U || policy.RedirectOutboundPort == policy.ProxyPort) return;
    if ((metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0U &&
        policy.ExemptProcessId != 0U && metadata->processId == policy.ExemptProcessId) return;
    if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
        remotePort = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
    } else if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) {
        event.Flags |= AI_SHIELD_EVENT_FLAG_IPV6;
        remotePort = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT].value.uint16;
    } else return;
    if (remotePort != (UINT16)policy.RedirectOutboundPort) return;
    event.RemotePort = remotePort;
    status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) { InterlockedIncrement64(&g_Status.DroppedTelemetry); return; }
    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0, (void**)&request, classifyOut);
    if (NT_SUCCESS(status) && request != NULL) {
        if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
            SOCKADDR_IN* remote = (SOCKADDR_IN*)&request->remoteAddressAndPort;
            remote->sin_family = AF_INET;
            remote->sin_addr.S_un.S_addr = RtlUlongByteSwap(0x7f000001U);
            remote->sin_port = RtlUshortByteSwap((UINT16)policy.ProxyPort);
        } else {
            SOCKADDR_IN6* remote = (SOCKADDR_IN6*)&request->remoteAddressAndPort;
            RtlZeroMemory(remote, sizeof(*remote));
            remote->sin6_family = AF_INET6;
            remote->sin6_addr.u.Byte[15] = 1U;
            remote->sin6_port = RtlUshortByteSwap((UINT16)policy.ProxyPort);
        }
        request->localRedirectHandle = g_RedirectHandle;
        request->localRedirectTargetPID = policy.ExemptProcessId;
        FwpsApplyModifiedLayerData0(classifyHandle, request, 0);
        InterlockedIncrement64(&g_Status.Redirected);
        event.LocalPort = policy.ProxyPort;
        event.Decision = FWP_ACTION_PERMIT;
        if (!AiShieldEventQueuePush(&g_EventQueue, &event)) InterlockedIncrement64(&g_Status.DroppedTelemetry);
    } else {
        InterlockedIncrement64(&g_Status.DroppedTelemetry);
    }
    FwpsReleaseClassifyHandle0(classifyHandle);
}

static NTSTATUS AiShieldCreateClose(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI AiShieldNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                                     const GUID* filterKey,
                                     const FWPS_FILTER1* filter) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
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
            policy->Mode <= AI_SHIELD_POLICY_ENFORCE && policy->BlockInboundPort <= 65535U &&
            policy->RedirectOutboundPort <= 65535U && policy->ProxyPort <= 65535U) {
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
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AI_SHIELD_IOCTL_REGISTER_BROKER &&
               stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(AI_SHIELD_BROKER_REGISTRATION)) {
        AI_SHIELD_BROKER_REGISTRATION* registration =
            (AI_SHIELD_BROKER_REGISTRATION*)irp->AssociatedIrp.SystemBuffer;
        if (registration->Version == AI_SHIELD_PROTOCOL_VERSION && registration->Size == sizeof(*registration) &&
            registration->ProcessId == (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId()) {
            AiShieldReplaceProcess(&g_BrokerProcess, PsGetCurrentProcess());
            status = STATUS_SUCCESS;
        } else status = STATUS_ACCESS_DENIED;
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AI_SHIELD_IOCTL_REGISTER_ISOLATED_PROCESS &&
               stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(AI_SHIELD_BROKER_REGISTRATION)) {
        AI_SHIELD_BROKER_REGISTRATION* registration =
            (AI_SHIELD_BROKER_REGISTRATION*)irp->AssociatedIrp.SystemBuffer;
        PEPROCESS process = NULL;
        if (AiShieldCurrentProcessIs(&g_BrokerProcess) &&
            registration->Version == AI_SHIELD_PROTOCOL_VERSION && registration->Size == sizeof(*registration) &&
            NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)registration->ProcessId, &process))) {
            AiShieldReplaceProcess(&g_IsolatedProcess, process);
            ObDereferenceObject(process);
            status = STATUS_SUCCESS;
        } else status = STATUS_ACCESS_DENIED;
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS AiShieldRegisterKernelCallout(PDEVICE_OBJECT device, const GUID* key,
                                               FWPS_CALLOUT_CLASSIFY_FN1 classifyFn, UINT32* id) {
    FWPS_CALLOUT1 callout = {0};
    callout.calloutKey = *key;
    callout.classifyFn = classifyFn;
    callout.notifyFn = AiShieldNotify;
    return FwpsCalloutRegister1(device, &callout, id);
}

static NTSTATUS AiShieldAddFilter(const GUID* layer, const GUID* key, UINT64 context) {
    FWPM_CALLOUT0 callout = {0};
    FWPM_FILTER0 filter = {0};
    NTSTATUS status;
    callout.calloutKey = *key;
    callout.providerKey = (GUID*)&kProvider;
    callout.applicableLayer = *layer;
    callout.displayData.name = L"AI Shield Callout";
    status = FwpmCalloutAdd0(g_Engine, &callout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;
    filter.layerKey = *layer;
    filter.subLayerKey = kSublayer;
    filter.providerKey = (GUID*)&kProvider;
    filter.displayData.name = L"AI Shield Filter";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *key;
    filter.rawContext = context;
    filter.weight.type = FWP_EMPTY;
    return FwpmFilterAdd0(g_Engine, &filter, NULL, NULL);
}

static void AiShieldUnload(PDRIVER_OBJECT driver) {
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\AIShieldWfp");
    PEPROCESS broker;
    PEPROCESS isolated;
    UNREFERENCED_PARAMETER(driver);
    if (g_Engine != NULL) { FwpmEngineClose0(g_Engine); g_Engine = NULL; }
    if (g_RedirectHandle != NULL) {
        FwpsRedirectHandleDestroy0(g_RedirectHandle);
        g_RedirectHandle = NULL;
    }
    if (g_RedirectIdV6 != 0U) FwpsCalloutUnregisterById0(g_RedirectIdV6);
    if (g_AcceptIdV6 != 0U) FwpsCalloutUnregisterById0(g_AcceptIdV6);
    if (g_ConnectIdV6 != 0U) FwpsCalloutUnregisterById0(g_ConnectIdV6);
    if (g_RedirectId != 0U) FwpsCalloutUnregisterById0(g_RedirectId);
    if (g_AcceptId != 0U) FwpsCalloutUnregisterById0(g_AcceptId);
    if (g_ConnectId != 0U) FwpsCalloutUnregisterById0(g_ConnectId);
    broker = (PEPROCESS)InterlockedExchangePointer((PVOID volatile*)&g_BrokerProcess, NULL);
    isolated = (PEPROCESS)InterlockedExchangePointer((PVOID volatile*)&g_IsolatedProcess, NULL);
    if (broker != NULL) ObDereferenceObject(broker);
    if (isolated != NULL) ObDereferenceObject(isolated);
    IoDeleteSymbolicLink(&link);
    if (g_Device != NULL) { IoDeleteDevice(g_Device); g_Device = NULL; }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\AIShieldWfp");
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\AIShieldWfp");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    FWPM_SESSION0 session = {0};
    FWPM_PROVIDER0 provider = {0};
    FWPM_SUBLAYER0 sublayer = {0};
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
    status = FwpsRedirectHandleCreate0(&kProvider, 0, &g_RedirectHandle);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return status; }
    status = AiShieldRegisterKernelCallout(g_Device, &kConnectCallout, AiShieldAuthorizeClassify, &g_ConnectId);
    if (NT_SUCCESS(status)) status = AiShieldRegisterKernelCallout(g_Device, &kAcceptCallout, AiShieldAuthorizeClassify, &g_AcceptId);
    if (NT_SUCCESS(status)) status = AiShieldRegisterKernelCallout(g_Device, &kRedirectCallout, AiShieldRedirectClassify, &g_RedirectId);
    if (NT_SUCCESS(status)) status = AiShieldRegisterKernelCallout(g_Device, &kConnectCalloutV6, AiShieldAuthorizeClassify, &g_ConnectIdV6);
    if (NT_SUCCESS(status)) status = AiShieldRegisterKernelCallout(g_Device, &kAcceptCalloutV6, AiShieldAuthorizeClassify, &g_AcceptIdV6);
    if (NT_SUCCESS(status)) status = AiShieldRegisterKernelCallout(g_Device, &kRedirectCalloutV6, AiShieldRedirectClassify, &g_RedirectIdV6);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return status; }
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"AI Shield Dynamic Session";
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_Engine);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(1U); }
    provider.providerKey = kProvider;
    provider.displayData.name = L"AI Shield Provider";
    status = FwpmProviderAdd0(g_Engine, &provider, NULL);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(2U); }
    sublayer.subLayerKey = kSublayer;
    sublayer.providerKey = (GUID*)&kProvider;
    sublayer.displayData.name = L"AI Shield Enforcement";
    sublayer.weight = 0x5000;
    status = FwpmSubLayerAdd0(g_Engine, &sublayer, NULL);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(3U); }
    status = AiShieldAddFilter(&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &kConnectCallout, 0U);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(4U); }
    status = AiShieldAddFilter(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &kAcceptCallout, 1U);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(5U); }
    status = AiShieldAddFilter(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, &kRedirectCallout, 2U);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(6U); }
    status = AiShieldAddFilter(&FWPM_LAYER_ALE_AUTH_CONNECT_V6, &kConnectCalloutV6, 0U);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(7U); }
    status = AiShieldAddFilter(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &kAcceptCalloutV6, 1U);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(8U); }
    status = AiShieldAddFilter(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, &kRedirectCalloutV6, 2U);
    if (!NT_SUCCESS(status)) { AiShieldUnload(driver); return AI_SHIELD_STAGE_STATUS(9U); }
    g_Device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
