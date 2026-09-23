//! User-mode client for the Phase 8 callout driver's device interface.
//!
//! The driver is **SOURCE ONLY** — it has never been compiled or loaded, so on this machine every
//! call here ends in "device not found". That is exactly the case the routing service must handle
//! correctly, and it is what the self-test exercises: **no driver ⇒ never "Protected"**.
//!
//! The structures must stay byte-identical to `experimental/windows-wfp-driver/mproxy-wfp.h`.
//! `abi_matches_header()` checks the sizes that the IOCTL contract depends on.

#![allow(dead_code)]

pub const MPROXY_ABI_VERSION: u32 = 1;
pub const DEVICE_PATH: &str = r"\\.\MProxyWfpRedirect";

/// Mirrors `MPROXY_REDIRECT_TARGET`. Fixed size, no pointers: the whole policy surface of the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RedirectTarget {
    pub version: u32,
    pub redirector_pid: u32,
    pub port_v4: u16,
    pub port_v6: u16,
    pub reserved: u32,
}

/// Mirrors `MPROXY_STATE`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DriverState {
    pub version: u32,
    pub active: u32,
    pub redirector_pid: u32,
    pub redirected_v4: u32,
    pub redirected_v6: u32,
    pub skipped_loop: u32,
    pub failed: u32,
}

/// The IOCTL codes, computed the same way `CTL_CODE` does in the header.
const FILE_DEVICE_NETWORK: u32 = 0x00000012;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;

const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_SET_TARGET: u32 = ctl_code(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_WRITE_ACCESS);
pub const IOCTL_CLEAR: u32 = ctl_code(FILE_DEVICE_NETWORK, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS);
pub const IOCTL_QUERY_STATE: u32 = ctl_code(FILE_DEVICE_NETWORK, 0x902, METHOD_BUFFERED, FILE_READ_ACCESS);

/// Sizes the IOCTL contract depends on. The driver rejects any request whose length is not exactly
/// these values, so a mismatch here would be an immediate, silent "invalid buffer size" at runtime.
pub fn abi_matches_header() -> Result<(), String> {
    // MPROXY_REDIRECT_TARGET: ULONG, ULONG, USHORT, USHORT, ULONG = 16 bytes with 4-byte alignment.
    if std::mem::size_of::<RedirectTarget>() != 16 {
        return Err(format!("RedirectTarget is {} bytes, header says 16", std::mem::size_of::<RedirectTarget>()));
    }
    // MPROXY_STATE: 7 x ULONG = 28 bytes.
    if std::mem::size_of::<DriverState>() != 28 {
        return Err(format!("DriverState is {} bytes, header says 28", std::mem::size_of::<DriverState>()));
    }
    Ok(())
}

#[derive(Debug)]
pub enum DriverError {
    /// The driver is not installed or not running.
    NotPresent(String),
    /// The device exists but the call failed.
    CallFailed(String),
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriverError::NotPresent(e) => write!(f, "driver not present: {e}"),
            DriverError::CallFailed(e) => write!(f, "driver call failed: {e}"),
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::io::{AsRawHandle, OwnedHandle};

    pub struct Driver {
        handle: OwnedHandle,
    }

    impl Driver {
        /// Opens the device. Only SYSTEM and Administrators pass the device ACL.
        pub fn open() -> Result<Driver, DriverError> {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(FILE_FLAG_NO_BUFFERING)
                .open(DEVICE_PATH)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => DriverError::NotPresent(e.to_string()),
                    _ => DriverError::CallFailed(e.to_string()),
                })?;
            Ok(Driver { handle: file.into() })
        }

        fn ioctl(&self, code: u32, input: &[u8], output: &mut [u8]) -> Result<u32, DriverError> {
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::System::IO::DeviceIoControl;
            let mut returned: u32 = 0;
            let ok = unsafe {
                DeviceIoControl(
                    self.handle.as_raw_handle() as HANDLE,
                    code,
                    if input.is_empty() { std::ptr::null() } else { input.as_ptr() as *const core::ffi::c_void },
                    input.len() as u32,
                    if output.is_empty() { std::ptr::null_mut() } else { output.as_mut_ptr() as *mut core::ffi::c_void },
                    output.len() as u32,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(DriverError::CallFailed(std::io::Error::last_os_error().to_string()));
            }
            Ok(returned)
        }

        pub fn set_target(&self, target: &RedirectTarget) -> Result<(), DriverError> {
            let bytes = unsafe { std::slice::from_raw_parts(target as *const _ as *const u8, std::mem::size_of::<RedirectTarget>()) };
            self.ioctl(IOCTL_SET_TARGET, bytes, &mut [])?;
            Ok(())
        }

        pub fn clear(&self) -> Result<(), DriverError> {
            self.ioctl(IOCTL_CLEAR, &[], &mut [])?;
            Ok(())
        }

        pub fn query_state(&self) -> Result<DriverState, DriverError> {
            let mut state = DriverState::default();
            let bytes = unsafe { std::slice::from_raw_parts_mut(&mut state as *mut _ as *mut u8, std::mem::size_of::<DriverState>()) };
            self.ioctl(IOCTL_QUERY_STATE, &[], bytes)?;
            Ok(state)
        }
    }
}

#[cfg(windows)]
pub use imp::Driver;

#[cfg(not(windows))]
pub struct Driver;

#[cfg(not(windows))]
impl Driver {
    pub fn open() -> Result<Driver, DriverError> {
        Err(DriverError::NotPresent("Windows only".into()))
    }
}
