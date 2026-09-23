/*++
EXPERIMENTAL — Phase 8 proof of concept.

    STATUS: SOURCE ONLY. This file has never been compiled, loaded, signed or executed.
    No WDK is available in the validation environment and no disposable VM exists, so every
    statement about its behaviour is CODE REVIEW ONLY, never runtime evidence.

What it does: a WFP callout at FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6 that rewrites the destination
of a connection to the local redirector and hands the original destination along in the local
redirect context. Nothing else.

What it deliberately does NOT do:
  * decide which application is routed - that lives in user mode, as filter conditions
    (FWPM_CONDITION_ALE_APP_ID + FWPM_CONDITION_ALE_USER_ID) on the filters that reference this
    callout. The kernel holds no application list, no paths, no SIDs, no policy;
  * parse anything (no JSON, no HTTP, no protocol), hold secrets, log traffic, or touch files;
  * provide any generic primitive: the device accepts three fixed-size structures and nothing else.

References (Microsoft Learn, retrieved 2026-09-23):
  Using bind or connect redirection
  https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
  FWPS_CONNECT_REQUEST0, FwpsRedirectHandleCreate0, FwpsQueryConnectionRedirectState0,
  FwpsAcquireClassifyHandle0, FwpsAcquireWritableLayerDataPointer0, FwpsApplyModifiedLayerData0.
--*/

#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include "mproxy-wfp.h"

#define MPROXY_TAG 'xPrM'

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD MproxyEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL MproxyEvtIoDeviceControl;

/* {0F0E6A31-6C1D-4E1E-9C8B-3A5B1C2D4E71} / {0F0E6A32-...}: placeholders. Regenerate with guidgen
   before any real build; two callouts (v4, v6) and one sublayer-less registration. */
DEFINE_GUID(MPROXY_CALLOUT_REDIRECT_V4, 0x0f0e6a31, 0x6c1d, 0x4e1e, 0x9c, 0x8b, 0x3a, 0x5b, 0x1c, 0x2d, 0x4e, 0x71);
DEFINE_GUID(MPROXY_CALLOUT_REDIRECT_V6, 0x0f0e6a32, 0x6c1d, 0x4e1e, 0x9c, 0x8b, 0x3a, 0x5b, 0x1c, 0x2d, 0x4e, 0x71);

typedef struct _MPROXY_GLOBALS {
    HANDLE              EngineHandle;        /* kernel-mode WFP engine handle              */
    UINT32              CalloutIdV4;
    UINT32              CalloutIdV6;
    BOOLEAN             CalloutV4Registered;
    BOOLEAN             CalloutV6Registered;
    HANDLE              RedirectHandle;      /* FwpsRedirectHandleCreate0, cached          */
    EX_SPIN_LOCK        TargetLock;          /* guards Target                              */
    MPROXY_REDIRECT_TARGET Target;           /* zeroed when inactive                       */
    volatile LONG       RedirectedV4;
    volatile LONG       RedirectedV6;
    volatile LONG       SkippedLoop;
    volatile LONG       Failed;
} MPROXY_GLOBALS;

static MPROXY_GLOBALS g = { 0 };

/*----------------------------------------------------------------------------------------------
  Policy accessor: a snapshot under a spin lock, so a classify never reads a half-written target.
----------------------------------------------------------------------------------------------*/
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN MproxyGetTarget(_Out_ MPROXY_REDIRECT_TARGET* out)
{
    KIRQL irql;
    BOOLEAN active;

    irql = ExAcquireSpinLockShared(&g.TargetLock);
    *out = g.Target;
    active = (out->RedirectorPid != 0) ? TRUE : FALSE;
    ExReleaseSpinLockShared(&g.TargetLock, irql);
    return active;
}

/*----------------------------------------------------------------------------------------------
  classifyFn1 for FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 / _V6.

  Order matters and follows the documented sequence:
    1. redirect state  (loop prevention, mandatory on Windows 8+)
    2. acquire classify handle
    3. acquire writable layer data
    4. save the original destination into localRedirectContext
    5. rewrite remoteAddressAndPort, set localRedirectTargetPID + localRedirectHandle
    6. apply, release
----------------------------------------------------------------------------------------------*/
_IRQL_requires_max_(DISPATCH_LEVEL)
static void NTAPI MproxyClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    NTSTATUS status;
    UINT64 classifyHandle = 0;
    BOOLEAN handleAcquired = FALSE;
    FWPS_CONNECT_REQUEST0* connectRequest = NULL;
    MPROXY_REDIRECT_TARGET target;
    MPROXY_REDIRECT_CONTEXT* context = NULL;
    FWPS_CONNECTION_REDIRECT_STATE redirectState;
    BOOLEAN isV4;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    isV4 = (inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) ? TRUE : FALSE;

    /* Never take away another callout's decision unless we can write one ourselves. */
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (!MproxyGetTarget(&target)) {
        return; /* inactive: behave as if this driver were not installed */
    }
    if (!isV4 && target.PortV6 == 0) {
        return; /* IPv6 redirection not configured; the service's BLOCK filters cover it */
    }

    /* (1) Loop prevention. A connection we already redirected, or the redirector's own outbound
       connection carrying our redirect records, must be left alone - otherwise the redirector's
       traffic to Xray, and Xray's traffic to the server, would be redirected back into ourselves.

       Documented handling of each state:
         NOT_REDIRECTED                  -> we may proxy;
         REDIRECTED_BY_SELF              -> permit / continue, do not redirect again;
         PREVIOUSLY_REDIRECTED_BY_SELF   -> "must not perform redirection", permit or block only;
         REDIRECTED_BY_OTHER             -> may proxy; we deliberately do NOT, so that another
                                            product's proxy keeps the flow and we never fight it. */
    redirectState = FwpsQueryConnectionRedirectState0(inMetaValues->redirectRecords, g.RedirectHandle, NULL);
    if (redirectState != FWPS_CONNECTION_NOT_REDIRECTED) {
        InterlockedIncrement(&g.SkippedLoop);
        return;
    }

    /* Belt and braces: never redirect the redirector itself, even before it has records to show. */
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID) &&
        inMetaValues->processId == (UINT64)target.RedirectorPid) {
        InterlockedIncrement(&g.SkippedLoop);
        return;
    }

    /* (2) */
    status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&g.Failed);
        return;
    }
    handleAcquired = TRUE;

    /* (3) */
    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0, (PVOID*)&connectRequest, classifyOut);
    if (!NT_SUCCESS(status) || connectRequest == NULL) {
        InterlockedIncrement(&g.Failed);
        goto cleanup;
    }

    /* Another callout already redirected this flow to a local proxy: per the documented pattern,
       permit and do not redirect again. */
    if (connectRequest->previousVersion != NULL &&
        connectRequest->previousVersion->modifierFilterId != filter->filterId &&
        connectRequest->previousVersion->localRedirectHandle != NULL) {
        InterlockedIncrement(&g.SkippedLoop);
        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)connectRequest, FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
        connectRequest = NULL;
        goto cleanup;
    }

    /* (4) Original destination for the redirector.
       OWNERSHIP CONTRACT (settled in Phase 8.5 against the documented FWPS_CONNECT_REQUEST0):
         * the callout allocates it ("a callout driver context area that the callout driver
           allocated by calling the ExAllocatePoolWithTag function");
         * "Starting with Windows 8, memory allocated for localRedirectContext will have its
           ownership taken by WFP, and will be freed when the proxied flow is removed."
       So: we must NOT free it once it has been handed over with FwpsApplyModifiedLayerData0, and we
       MUST free it ourselves on any path that fails before that hand-over. That is exactly what the
       `context = NULL` below and the cleanup block implement.
       https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0 */
    context = (MPROXY_REDIRECT_CONTEXT*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(MPROXY_REDIRECT_CONTEXT), MPROXY_TAG);
    if (context == NULL) {
        InterlockedIncrement(&g.Failed);
        goto cleanup; /* fail closed: no redirect, and the service's BLOCK filter denies the flow */
    }
    RtlZeroMemory(context, sizeof(*context));
    context->Magic = MPROXY_CONTEXT_MAGIC;
    context->Version = MPROXY_ABI_VERSION;

    if (isV4) {
        context->AddressFamily = AF_INET;
        context->OriginalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
        /* WFP presents IPv4 addresses in host byte order; store network order for the redirector. */
        {
            UINT32 hostAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
            UINT32 netAddr = RtlUlongByteSwap(hostAddr);
            RtlCopyMemory(context->OriginalAddress, &netAddr, sizeof(netAddr));
        }
    } else {
        context->AddressFamily = AF_INET6;
        context->OriginalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT].value.uint16;
        RtlCopyMemory(context->OriginalAddress,
                      inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
                      sizeof(FWP_BYTE_ARRAY16));
    }

    connectRequest->localRedirectContext = context;
    connectRequest->localRedirectContextSize = sizeof(MPROXY_REDIRECT_CONTEXT);
    context = NULL; /* owned by the layer data from here on */

    /* (5) Destination becomes the local redirector. Keep the address zone consistent: if the flow
       has no explicit local address, use loopback; otherwise reuse the local address, as documented. */
    if (isV4) {
        if (INETADDR_ISANY((PSOCKADDR)&connectRequest->localAddressAndPort)) {
            INETADDR_SETLOOPBACK((PSOCKADDR)&connectRequest->remoteAddressAndPort);
        } else {
            INETADDR_SET_ADDRESS((PSOCKADDR)&connectRequest->remoteAddressAndPort,
                                 INETADDR_ADDRESS((PSOCKADDR)&connectRequest->localAddressAndPort));
        }
        INETADDR_SET_PORT((PSOCKADDR)&connectRequest->remoteAddressAndPort, RtlUshortByteSwap(target.PortV4));
    } else {
        if (INETADDR_ISANY((PSOCKADDR)&connectRequest->localAddressAndPort)) {
            INETADDR_SETLOOPBACK((PSOCKADDR)&connectRequest->remoteAddressAndPort);
        } else {
            INETADDR_SET_ADDRESS((PSOCKADDR)&connectRequest->remoteAddressAndPort,
                                 INETADDR_ADDRESS((PSOCKADDR)&connectRequest->localAddressAndPort));
        }
        INETADDR_SET_PORT((PSOCKADDR)&connectRequest->remoteAddressAndPort, RtlUshortByteSwap(target.PortV6));
    }

    connectRequest->localRedirectTargetPID = target.RedirectorPid;
    connectRequest->localRedirectHandle = g.RedirectHandle;

    /* (6) */
    FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)connectRequest, 0);
    connectRequest = NULL;

    InterlockedIncrement(isV4 ? &g.RedirectedV4 : &g.RedirectedV6);
    classifyOut->actionType = FWP_ACTION_PERMIT;

cleanup:
    if (context != NULL) {
        ExFreePoolWithTag(context, MPROXY_TAG);
    }
    if (connectRequest != NULL) {
        /* Acquired but not applied: hand the data back unmodified. */
        FwpsApplyModifiedLayerData0(classifyHandle, (PVOID)connectRequest, FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
    }
    if (handleAcquired) {
        FwpsReleaseClassifyHandle0(classifyHandle);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS NTAPI MproxyNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS MproxyRegisterCallout(_In_ WDFDEVICE device, _In_ const GUID* calloutKey, _In_ const GUID* layerKey, _Out_ UINT32* calloutId)
{
    FWPS_CALLOUT3 sCallout = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPM_DISPLAY_DATA0 display = { 0 };
    NTSTATUS status;

    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = MproxyClassify;
    sCallout.notifyFn = MproxyNotify;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(device), &sCallout, calloutId);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    display.name = L"MProxy per-app connect redirect";
    display.description = L"Redirects selected applications' connections to the local MProxy redirector";
    mCallout.calloutKey = *calloutKey;
    mCallout.displayData = display;
    mCallout.applicableLayer = *layerKey;

    /* Filters that reference this callout are added by the user-mode routing service, together with
       the application conditions. The callout object itself carries no policy. */
    return FwpmCalloutAdd0(g.EngineHandle, &mCallout, NULL, NULL);
}

/*----------------------------------------------------------------------------------------------
  IOCTL handling. Fixed-size buffered transfers only; every field is validated before use.
----------------------------------------------------------------------------------------------*/
_Use_decl_annotations_
VOID MproxyEvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outLength, size_t inLength, ULONG code)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t written = 0;
    KIRQL irql;

    UNREFERENCED_PARAMETER(queue);

    switch (code) {
    case MPROXY_IOCTL_SET_TARGET: {
        MPROXY_REDIRECT_TARGET* in = NULL;
        MPROXY_REDIRECT_TARGET validated;

        if (inLength != sizeof(MPROXY_REDIRECT_TARGET)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
        status = WdfRequestRetrieveInputBuffer(request, sizeof(*in), (PVOID*)&in, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        validated = *in; /* copy out of the buffer before validating, then use only the copy */

        if (validated.Version != MPROXY_ABI_VERSION ||
            validated.Reserved != 0 ||
            validated.RedirectorPid == 0 ||
            validated.PortV4 == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        irql = ExAcquireSpinLockExclusive(&g.TargetLock);
        g.Target = validated;
        ExReleaseSpinLockExclusive(&g.TargetLock, irql);
        status = STATUS_SUCCESS;
        break;
    }

    case MPROXY_IOCTL_CLEAR:
        irql = ExAcquireSpinLockExclusive(&g.TargetLock);
        RtlZeroMemory(&g.Target, sizeof(g.Target));
        ExReleaseSpinLockExclusive(&g.TargetLock, irql);
        status = STATUS_SUCCESS;
        break;

    case MPROXY_IOCTL_QUERY_STATE: {
        MPROXY_STATE* out = NULL;
        MPROXY_REDIRECT_TARGET target;

        if (outLength != sizeof(MPROXY_STATE)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(*out), (PVOID*)&out, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        RtlZeroMemory(out, sizeof(*out));
        out->Version = MPROXY_ABI_VERSION;
        out->Active = MproxyGetTarget(&target) ? 1 : 0;
        out->RedirectorPid = target.RedirectorPid;
        out->RedirectedV4 = (ULONG)g.RedirectedV4;
        out->RedirectedV6 = (ULONG)g.RedirectedV6;
        out->SkippedLoop = (ULONG)g.SkippedLoop;
        out->Failed = (ULONG)g.Failed;
        written = sizeof(*out);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        break;
    }

    WdfRequestCompleteWithInformation(request, status, written);
}

_Use_decl_annotations_
VOID MproxyEvtDriverUnload(WDFDRIVER driver)
{
    UNREFERENCED_PARAMETER(driver);

    /* Stop redirecting first, then tear down, so no classify can run against freed state. */
    {
        KIRQL irql = ExAcquireSpinLockExclusive(&g.TargetLock);
        RtlZeroMemory(&g.Target, sizeof(g.Target));
        ExReleaseSpinLockExclusive(&g.TargetLock, irql);
    }

    /* Remove the management-plane callout objects explicitly. The engine session is dynamic, so BFE
       would remove them when the handle closes, but an explicit delete keeps "no stale WFP objects
       after unload" true even if the close path is ever changed. Order matters: management objects
       first, then the kernel registrations. */
    if (g.EngineHandle != NULL) {
        FwpmCalloutDeleteByKey0(g.EngineHandle, &MPROXY_CALLOUT_REDIRECT_V4);
        FwpmCalloutDeleteByKey0(g.EngineHandle, &MPROXY_CALLOUT_REDIRECT_V6);
    }

    /* FwpsCalloutUnregisterById0 returns STATUS_DEVICE_BUSY while filters still reference the
       callout or flows are still being classified. The driver must not unload until both succeed;
       the notifyFn is where a production driver tracks that. REVIEW ITEM for the first VM run:
       confirm the unload path against Driver Verifier with live flows. */
    if (g.CalloutV4Registered) {
        if (NT_SUCCESS(FwpsCalloutUnregisterById0(g.CalloutIdV4))) {
            g.CalloutV4Registered = FALSE;
        }
    }
    if (g.CalloutV6Registered) {
        if (NT_SUCCESS(FwpsCalloutUnregisterById0(g.CalloutIdV6))) {
            g.CalloutV6Registered = FALSE;
        }
    }
    if (g.RedirectHandle != NULL) {
        FwpsRedirectHandleDestroy0(g.RedirectHandle);
        g.RedirectHandle = NULL;
    }
    if (g.EngineHandle != NULL) {
        FwpmEngineClose0(g.EngineHandle);
        g.EngineHandle = NULL;
    }
}

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    DECLARE_CONST_UNICODE_STRING(deviceName, MPROXY_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symbolicName, MPROXY_SYMBOLIC_NAME);
    DECLARE_CONST_UNICODE_STRING(sddl, MPROXY_DEVICE_SDDL);

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = MproxyEvtDriverUnload;

    status = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceInit = WdfControlDeviceInitAllocate(driver, &sddl);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    status = WdfDeviceCreateSymbolicLink(device, &symbolicName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = MproxyEvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    WdfControlFinishInitializing(device);

    /* Dynamic session: every management object this driver adds (the callouts) is removed by BFE
       when the engine handle closes, including after an abnormal stop. Nothing we create outlives
       the driver. */
    {
        FWPM_SESSION0 session = { 0 };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g.EngineHandle);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FwpsRedirectHandleCreate0(&MPROXY_CALLOUT_REDIRECT_V4, 0, &g.RedirectHandle);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }

    status = MproxyRegisterCallout(device, &MPROXY_CALLOUT_REDIRECT_V4, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, &g.CalloutIdV4);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    g.CalloutV4Registered = TRUE;

    status = MproxyRegisterCallout(device, &MPROXY_CALLOUT_REDIRECT_V6, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, &g.CalloutIdV6);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    g.CalloutV6Registered = TRUE;

    return STATUS_SUCCESS;

fail:
    MproxyEvtDriverUnload(driver);
    return status;
}
