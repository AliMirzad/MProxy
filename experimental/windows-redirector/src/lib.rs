//! EXPERIMENTAL Phase 8: the user-mode half of true per-app routing.
//!
//! The redirector accepts connections that the kernel callout redirected to loopback, recovers the
//! **original destination**, and forwards the stream through the product's existing *authenticated*
//! local proxy inbound into Xray. The selected application never learns about a proxy, and the local
//! proxy is never opened up to unrelated processes: the credentials live in the redirector, not in
//! the application (Phase 5 F5 is preserved).
//!
//! Two sources of the original destination:
//! * `RedirectSource::Wfp` — `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` on the accepted socket.
//!   Compiled and callable, but never exercised: no driver exists to produce a context.
//! * `RedirectSource::Simulated` — a destination supplied by the harness, standing in for what the
//!   kernel would have provided. Everything downstream of the kernel is then real.
//!
//! Nothing here speaks VLESS/VMess, reads configuration, or touches the network outside loopback and
//! the destination Xray dials for it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub mod attribution;

/// Where a connection's original destination came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectSource {
    /// Recovered from the WFP local redirect context (requires the callout driver).
    Wfp,
    /// Supplied out of band by the test harness in place of the kernel.
    Simulated,
}

impl RedirectSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RedirectSource::Wfp => "wfp-redirect-context",
            RedirectSource::Simulated => "simulated (no driver present)",
        }
    }
}

/// Credentials for the local authenticated proxy inbound. Never logged.
#[derive(Clone)]
pub struct UpstreamProxy {
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl std::fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UpstreamProxy {{ port: {}, user: <redacted>, pass: <redacted> }}", self.port)
    }
}

/// Opens a tunnel to `destination` through the local authenticated HTTP proxy inbound.
///
/// The transparent application cannot answer a proxy challenge, so the redirector answers it. That
/// keeps the inbound authenticated: an unrelated local process that finds the port still cannot use
/// it.
pub fn tunnel_through_proxy(upstream: &UpstreamProxy, destination: &str) -> Result<TcpStream, String> {
    use base64::Engine;
    let mut s = TcpStream::connect(("127.0.0.1", upstream.port)).map_err(|e| format!("connect to local inbound: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", upstream.user, upstream.pass));
    let req = format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\nProxy-Authorization: Basic {auth}\r\nProxy-Connection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("send CONNECT: {e}"))?;

    // Read just the status line and headers, byte by byte: the body belongs to the tunnelled stream.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match s.read(&mut byte) {
            Ok(0) => return Err("local inbound closed the connection during CONNECT".into()),
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
                if head.len() > 8192 {
                    return Err("CONNECT response too large".into());
                }
            }
            Err(e) => return Err(format!("read CONNECT response: {e}")),
        }
    }
    let status = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
    if !status.contains(" 200") {
        return Err(format!("CONNECT refused: {status}"));
    }
    Ok(s)
}

/// Copies bytes in both directions until either side closes. Returns (client→upstream, upstream→client).
pub fn pump(client: TcpStream, upstream: TcpStream) -> (u64, u64) {
    let (mut c_read, mut c_write) = (client.try_clone().expect("clone client"), client);
    let (mut u_read, mut u_write) = (upstream.try_clone().expect("clone upstream"), upstream);

    let up = std::thread::spawn(move || {
        let n = std::io::copy(&mut c_read, &mut u_write).unwrap_or(0);
        let _ = u_write.shutdown(std::net::Shutdown::Write);
        n
    });
    let down = std::io::copy(&mut u_read, &mut c_write).unwrap_or(0);
    let _ = c_write.shutdown(std::net::Shutdown::Write);
    (up.join().unwrap_or(0), down)
}

/// Reads the original destination from the WFP local redirect context of an accepted socket.
///
/// NOT EXERCISED: without the callout driver no socket carries a redirect context, so this returns
/// `Ok(None)` on this machine. Kept compiled so the code path is type-checked and reviewable.
#[cfg(windows)]
pub fn original_destination_from_wfp(socket: &TcpStream) -> Result<Option<SocketAddr>, String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, WSAIoctl, SOCKET};

    // SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, from mstcpip.h:
    // _WSAIORW(IOC_VENDOR, 108) = IOC_IN | IOC_OUT | IOC_VENDOR | 108
    const SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT: u32 = 0xC000_0000 | 0x1800_0000 | 108;

    // Must mirror MPROXY_REDIRECT_CONTEXT in the driver header.
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct RedirectContext {
        magic: u32,
        version: u32,
        family: u16,
        port: u16,
        address: [u8; 16],
        scope_id: u32,
    }
    const MAGIC: u32 = 0x4D50_5843;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 23;

    let mut ctx = RedirectContext::default();
    let mut returned: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            std::ptr::null_mut(),
            0,
            &mut ctx as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<RedirectContext>() as u32,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        // No driver, or this connection was not redirected: not an error for the PoC.
        let err = unsafe { WSAGetLastError() };
        return Err(format!("WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT) failed: {err}"));
    }
    if returned as usize != std::mem::size_of::<RedirectContext>() || ctx.magic != MAGIC {
        return Ok(None);
    }
    let addr = match ctx.family {
        AF_INET => SocketAddr::from((Ipv4Addr::from([ctx.address[0], ctx.address[1], ctx.address[2], ctx.address[3]]), ctx.port)),
        AF_INET6 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&ctx.address);
            SocketAddr::from((Ipv6Addr::from(b), ctx.port))
        }
        _ => return Ok(None),
    };
    Ok(Some(addr))
}

#[cfg(not(windows))]
pub fn original_destination_from_wfp(_socket: &TcpStream) -> Result<Option<SocketAddr>, String> {
    Err("Windows only".into())
}
