//! Destination-side ground truth: which local process owns a TCP connection.
//!
//! The controlled target uses this to say *who* actually connected to it — the unaware client
//! itself (direct) or Xray (tunnelled). Client-side return codes are not evidence; this is
//! (§39: capture evidence on both sides).

/// PID owning the local TCP endpoint `local_port` (IPv4), if any.
#[cfg(windows)]
pub fn owner_pid_of_local_port(local_port: u16) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL};
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut size: u32 = 0;
    unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { GetExtendedTcpTable(buf.as_mut_ptr() as *mut core::ffi::c_void, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) };
    if rc != 0 {
        return None;
    }
    // MIB_TCPTABLE_OWNER_PID: { DWORD dwNumEntries; MIB_TCPROW_OWNER_PID table[]; }
    let count = u32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    for i in 0..count {
        let off = 4 + i * row_size;
        if off + row_size > buf.len() {
            break;
        }
        let row = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const MIB_TCPROW_OWNER_PID) };
        // dwLocalPort is in network byte order in the low 16 bits.
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        if port == local_port {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(not(windows))]
pub fn owner_pid_of_local_port(_local_port: u16) -> Option<u32> {
    None
}

/// Executable name of a PID, for readable evidence ("xray.exe" / "unaware-client.exe").
#[cfg(windows)]
pub fn process_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 512];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        Some(path.rsplit('\\').next().unwrap_or(&path).to_string())
    }
}

#[cfg(not(windows))]
pub fn process_name(_pid: u32) -> Option<String> {
    None
}
