// ============================================================================
// Mirrors: jpmail/src/jif/net/JifSocketFactory.jif
//
// JifSocketFactory provides socket connections. In JPmail:
//   - POP3 sockets are used at the authenticated principal's level
//   - SMTP sockets start at Public, transition after DIGEST-MD5 authentication
// ============================================================================

/// A network connection.
///
/// In JPmail: `Socket[L]{L}` -- the socket object itself carries a label.
#[derive(Debug)]
pub struct SecureSocket {
    /// Server hostname (public, visible to DNS and network).
    pub host: String,
    /// Server port number (public).
    pub port: u16,
    /// Whether TLS is in use (public).
    pub use_ssl: bool,
}

impl SecureSocket {
    /// Create a plain TCP connection.
    /// Mirrors: createSocket(String host, int port) in JifSocketFactory.jif
    ///
    /// In JPmail: used by MailReaderCrypto for the POP3 connection on port 110
    /// and by MailSenderCrypto for SMTP on port 587 (before STARTTLS).
    pub fn create(host: impl std::fmt::Display, port: u16) -> Self {
        println!("[Socket] Connecting {}:{} (plain TCP)", host, port);
        SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: false,
        }
    }

    /// Create an SSL/TLS connection.
    /// Mirrors: the SSL-variant of createSocket() in JifSocketFactory.jif
    ///
    /// In JPmail: used for POP3-over-SSL (port 995) and SMTPS (port 465).
    pub fn create_ssl(host: &str, port: u16) -> Self {
        println!("[Socket] Connecting {}:{} (SSL/TLS)", host, port);
        SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: true,
        }
    }

    /// Read a line from the socket.
    ///
    /// In JPmail: the BufferedReader wrapping the socket preserves the label.
    pub fn read_line(&self) -> String {
        // Stub: real impl reads from TCP/SSL stream
        format!("+OK server@{}:{} ready", self.host, self.port)
    }

    /// Write data to the socket.
    ///
    /// In JPmail: the PrintStream wrapping the output carries the label.
    pub fn write_line(&self, data: String) {
        println!("[Socket {}:{}] >> {}", self.host, self.port, data);
    }

    /// Send a public (unlabeled) command to the server.
    /// Convenience wrapper for protocol commands like "QUIT", "NOOP".
    pub fn send_command(&self, cmd: &str) {
        println!("[Socket {}:{}] >> {}", self.host, self.port, cmd);
    }
}
