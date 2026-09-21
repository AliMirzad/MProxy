//! Loopback port helpers. Nothing here ever binds a non-loopback address.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// Asks the OS for a free ephemeral loopback port. The port is released before Xray binds it.
/// That leaves a tiny race window: if Xray then fails to bind, the caller retries with a new port.
pub fn ephemeral_port() -> std::io::Result<u16> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(l.local_addr()?.port())
}

/// True if nothing is listening on 127.0.0.1:port and we can bind it.
pub fn is_free(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// Like [`is_free`], but tolerates a port that our own Xray released a moment ago
/// (the OS can take a short while to free a listening socket after the process exits).
pub fn is_free_soon(port: u16, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if is_free(port) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits until something accepts TCP connections on 127.0.0.1:port.
pub fn wait_listening(port: u16, timeout: Duration, mut still_alive: impl FnMut() -> bool) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return true;
        }
        if !still_alive() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupied_port_detected() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let p = l.local_addr().unwrap().port();
        assert!(!is_free(p));
        assert!(wait_listening(p, Duration::from_millis(500), || true));
        drop(l);
        assert!(is_free(p));
        let e = ephemeral_port().unwrap();
        assert!(e > 0);
    }
}
