// ============================================================================
// Mirrors: jpmail/src/jif/net/JifSocketFactory.jif
//
// Jif source:
//   class JifSocketFactory[label L] {
//       Socket[L]{L} createSocket(String host, int port)
//       Socket[L]{L} createSocket(String host, int port, boolean autoClose)
//       Socket[L]{L} createSocket(InetAddress address, int port)
//       Socket[L]{L} createSocket(InetAddress address, int port,
//                                  InetAddress localAddress, int localPort)
//       Socket[L]{L} createSocket(String host, int port,
//                                  InetAddress localHost, int localPort)
//   }
//
// JifSocketFactory provides labeled socket connections so that data flowing
// through the socket carries the appropriate security label. In JPmail:
//   - POP3 sockets are labeled at the authenticated principal's level (L=A for alice)
//   - SMTP sockets start at Public, transition after DIGEST-MD5 authentication
// ============================================================================

use typing_rules::implicit::InvisibleSideEffectFree;
use typing_rules::lattice::*;

/// A network connection labeled with security level L.
///
/// All data read from this socket returns `Labeled<String, L>`.
/// All data written must flow to L (`Src: FlowsTo<L>`).
///
/// In JPmail: `Socket[L]{L}` — the socket object itself is labeled L,
/// meaning the socket handle cannot be passed to lower-clearance code.
#[derive(Debug)]
pub struct SecureSocket<L: Label> {
    /// Server hostname (String{} in Jif — public, visible to DNS and network).
    pub host: String, // String{} host
    /// Server port number (int{} in Jif — public).
    pub port: u16, // int{} port
    /// Whether TLS is in use (boolean{} — public).
    pub use_ssl: bool, // boolean{} useSSL
    _label: std::marker::PhantomData<L>,
}

impl<L: Label> SecureSocket<L> {
    /// Create a plain TCP connection.
    /// Mirrors: createSocket(String host, int port) in JifSocketFactory.jif
    ///
    /// Returns `Labeled<Self, L>` — the socket handle is labeled L,
    /// so it can only be used within L-clearance contexts.
    ///
    /// In JPmail: used by MailReaderCrypto for the POP3 connection on port 110
    /// and by MailSenderCrypto for SMTP on port 587 (before STARTTLS).
    pub fn create(host: impl std::fmt::Display, port: u16) -> Labeled<Self, L> {
        println!("[Socket] Connecting {}:{} (plain TCP)", host, port);
        Labeled::new(SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: false,
            _label: std::marker::PhantomData,
        })
    }

    /// Create an SSL/TLS connection.
    /// Mirrors: the SSL-variant of createSocket() in JifSocketFactory.jif
    ///
    /// In JPmail: used for POP3-over-SSL (port 995) and SMTPS (port 465).
    pub fn create_ssl(host: &str, port: u16) -> Labeled<Self, L> {
        println!("[Socket] Connecting {}:{} (SSL/TLS)", host, port);
        Labeled::new(SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: true,
            _label: std::marker::PhantomData,
        })
    }

    /// Read a line from the socket.
    ///
    /// Returns `Labeled<String, L>` — data received from this socket carries
    /// label L. In JPmail: the BufferedReader wrapping the socket is typed
    /// as `BufferedReader[L]{L}` so all reads preserve the label.
    pub fn read_line(&self) -> Labeled<String, L> {
        // Stub: real impl reads from TCP/SSL stream
        Labeled::new(format!("+OK server@{}:{} ready", self.host, self.port))
    }

    /// Write labeled data to the socket.
    ///
    /// The constraint `Src: FlowsTo<L>` ensures we cannot send data from a
    /// higher label over a lower-labeled channel:
    ///   - Writing `Labeled<String, A>` to `SecureSocket<Public>` is a COMPILE ERROR
    ///   - This prevents alice's secret commands from being visible on a public channel
    ///
    /// In JPmail: the PrintStream wrapping the output is typed `PrintStream[L]{L}`.
    pub fn write_line<Src: Label + LEQ<L>>(&self, data: Labeled<String, Src>) {
        println!("[Socket {}:{}] >> [labeled data]", self.host, self.port);
    }

    /// Send a public (unlabeled) command to the server.
    /// Convenience wrapper for protocol commands like "QUIT", "NOOP".
    pub fn send_command(&self, cmd: &str) {
        println!("[Socket {}:{}] >> {}", self.host, self.port, cmd);
    }
}

unsafe impl<L: Label> InvisibleSideEffectFree for SecureSocket<L> {}
