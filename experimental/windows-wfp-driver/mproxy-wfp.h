/*++
EXPERIMENTAL — Phase 8 proof of concept. SOURCE ONLY: never compiled, never loaded, never signed.
Shared definitions between the kernel driver and the user-mode routing service.

The interface is deliberately tiny. Everything that decides *which* application is routed lives in
user mode, as WFP filter conditions (executable path + user SID) installed by the service. The kernel
is told only where the local redirector listens and which process it is, so a malformed or hostile
IOCTL cannot express a policy at all.
--*/

#pragma once

#define MPROXY_DEVICE_NAME      L"\\Device\\MProxyWfpRedirect"
#define MPROXY_SYMBOLIC_NAME    L"\\DosDevices\\MProxyWfpRedirect"

/* SYSTEM and Administrators only, no inherited ACEs. The routing service runs as LocalSystem;
   an ordinary user process cannot open the device at all. */
#define MPROXY_DEVICE_SDDL      L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

#define MPROXY_IOCTL_SET_TARGET  CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MPROXY_IOCTL_CLEAR       CTL_CODE(FILE_DEVICE_NETWORK, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define MPROXY_IOCTL_QUERY_STATE CTL_CODE(FILE_DEVICE_NETWORK, 0x902, METHOD_BUFFERED, FILE_READ_ACCESS)

#define MPROXY_ABI_VERSION 1

/* Fixed-size, no embedded pointers, no variable-length arrays: METHOD_BUFFERED copies it in full,
   so the driver never touches a user-mode pointer and every field is bounds-checked by construction. */
typedef struct _MPROXY_REDIRECT_TARGET {
    ULONG  Version;        /* must equal MPROXY_ABI_VERSION                       */
    ULONG  RedirectorPid;  /* PID of the local redirector; must be non-zero       */
    USHORT PortV4;         /* host byte order; must be non-zero                   */
    USHORT PortV6;         /* host byte order; 0 = do not redirect IPv6 (blocked
                              instead by the service's WFP filters)               */
    ULONG  Reserved;       /* must be zero                                        */
} MPROXY_REDIRECT_TARGET, *PMPROXY_REDIRECT_TARGET;

typedef struct _MPROXY_STATE {
    ULONG Version;
    ULONG Active;            /* 0 = no redirect target set                        */
    ULONG RedirectorPid;
    ULONG RedirectedV4;      /* counters, for diagnostics only; never addresses   */
    ULONG RedirectedV6;
    ULONG SkippedLoop;       /* connections left alone by loop prevention         */
    ULONG Failed;
} MPROXY_STATE, *PMPROXY_STATE;

/* Original destination handed to the redirector through the WFP local redirect context, read back
   with SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT. Fixed size, version-tagged. */
#define MPROXY_CONTEXT_MAGIC 0x4D505843UL /* 'MPXC' */

typedef struct _MPROXY_REDIRECT_CONTEXT {
    ULONG  Magic;
    ULONG  Version;
    USHORT AddressFamily;   /* AF_INET or AF_INET6            */
    USHORT OriginalPort;    /* host byte order                */
    UCHAR  OriginalAddress[16];
    ULONG  ScopeId;
} MPROXY_REDIRECT_CONTEXT, *PMPROXY_REDIRECT_CONTEXT;
