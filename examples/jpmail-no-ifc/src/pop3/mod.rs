// ============================================================================
// Mirrors: jpmail/src/pop3/MailReaderCrypto.jif
//
// Jif source (abridged):
//   class MailReaderCrypto[label L] {
//       // POP3 connection fields
//       String{} server;
//       String{L} username;
//       char{L}[] password;
//       Socket[L]{L} socket;
//       PrintStream[L]{L} out;
//       BufferedReader[L]{L} in;
//
//       void connect(String server)   throws IOException
//       void authenticate()           throws IOException
//       JPMailMessage[L][] getMessages()
//       void disconnect()
//   }
//
// MailReaderCrypto is the jpgetmail executable.
// Usage: make pop3/MailReaderCrypto ARGS='[principal] [server] [username]'
//
// In the demo:
//   alice runs MailReaderCrypto  -> retrieves and decrypts her mail
//   bono  runs MailReaderCrypto  -> retrieves public mail only
//   bono CANNOT decrypt or display alice's messages
// ============================================================================

pub mod content;
pub mod header;
pub mod message;
pub mod part;

use crate::net::SecureSocket;
use crate::password::Password;
use crate::policy::KeyPrincipal;
use crate::pop3::message::{JPMailMessage, MimeMailMessage};
use crate::smtp::auth::DigestApop;

/// POP3 mail retrieval client.
///
/// In JPmail, MailReaderCrypto is invoked as jpgetmail:
///   make pop3/MailReaderCrypto ARGS='alice jpmail.cse.psu.edu alice'
pub struct MailReaderCrypto {
    /// POP3 server hostname (public, server address is not secret).
    pub server: String,
    /// Authenticated username (ties this session to a principal).
    pub username: String,
    /// POP3 password (secret credential).
    pub password: String,
    /// The key principal used to decrypt messages.
    pub key_principal: KeyPrincipal,
    /// Retrieved and decrypted messages.
    pub messages: Vec<JPMailMessage>,
    /// Raw encrypted messages from the server (still on-wire format).
    encrypted_spool: Vec<MimeMailMessage>,
}

impl MailReaderCrypto {
    /// Create a new mail reader.
    /// Mirrors: MailReaderCrypto constructor.
    pub fn new(server: &str, username: &str, password: String) -> Self {
        let key_principal = KeyPrincipal::new(
            username,
            &format!("demo/certs-{}/", username),
            password.clone(),
        );
        MailReaderCrypto {
            server: server.to_string(),
            username: username.to_string(),
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    /// Load credentials from encrypted password files on disk.
    /// Mirrors: the password reading path in MailReaderCrypto.jif using Password.jif
    pub fn from_password_file(server: &str, username: &str, cert_dir: &str) -> Self {
        let pw_file = Password::new(&format!("demo/passwd-{}/", username));
        let password = pw_file.get_password();
        let key_principal = KeyPrincipal::new(username, cert_dir, password.clone());
        MailReaderCrypto {
            server: server.to_string(),
            username: username.to_string(),
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    /// Open a POP3 connection.
    /// Mirrors: connect() in MailReaderCrypto.jif
    ///
    /// In JPmail: opens Socket to server:110 (or 995 for POP3S).
    pub fn connect(&self) -> SecureSocket {
        println!("[POP3] Connecting to {}:110", self.server);
        let socket = SecureSocket::create(&self.server, 110);
        // Read server greeting (e.g. "+OK JPmail POP3 server ready")
        let greeting = socket.read_line();
        println!("[POP3] Server: {}", greeting);
        socket
    }

    /// Authenticate with APOP or DIGEST-MD5.
    /// Mirrors: authenticate() in MailReaderCrypto.jif
    ///
    /// In JPmail: MailReaderCrypto sends "USER" + "PASS" or APOP.
    pub fn authenticate(&self, socket: &SecureSocket) -> bool {
        println!("[POP3] Authenticating (APOP)");
        // In JPmail: DigestMD5.getAPOPDigest(password, server_challenge)
        let apop = DigestApop::new(self.password.clone());
        let challenge = socket.read_line(); // "+OK <timestamp@server>" challenge
        let digest = apop.compute_apop_digest(challenge);

        // Send USER + APOP response
        let user_cmd = format!("USER {}", self.username);
        socket.write_line(user_cmd);
        let _ = digest;

        let response = socket.read_line();
        response.starts_with("+OK")
    }

    /// Retrieve all messages from the server.
    /// Mirrors: getMessages() in MailReaderCrypto.jif
    ///
    /// In JPmail: issues "LIST", then "RETR n" for each message.
    /// Parses each response as MimeMailMessage from a BufferedReader.
    pub fn fetch_encrypted_messages(&mut self, socket: &SecureSocket) {
        println!("[POP3] Fetching message list (LIST)...");
        socket.send_command("LIST");
        let _list_response = socket.read_line();
        println!("[POP3] [list response]");

        // In JPmail: iterates RETR 1, RETR 2, ... until no more messages
        // Stub: simulate two messages in alice's spool
        println!("[POP3] RETR 1");
        let raw = socket.read_line();
        let _ = raw;

        // Build stub encrypted message (in real impl: parsed from MIME stream)
        let crypto_info: String = "[rsa_wrapped_aes_key_stub]".to_string();
        let header = crate::pop3::header::MimeHeader::new(
            &self.username,
            "sender@example.com",
            "(encrypted subject stub)",
            crypto_info,
        );
        let encrypted_body_bytes: Vec<u8> = b"[encrypted_body_stub]".to_vec();
        let part = crate::pop3::part::MimePart::make_base64(encrypted_body_bytes, "body.enc");
        let mime_msg = MimeMailMessage { header, parts: vec![part] };
        self.encrypted_spool.push(mime_msg);
    }

    /// Decrypt all fetched messages using the owner's private key.
    /// Mirrors: the decryption loop in MailReaderCrypto.jif
    ///
    /// Requires the private key from the key principal.
    /// Produces `Vec<JPMailMessage>` -- plaintext messages.
    pub fn decrypt_messages(&mut self) {
        println!("[POP3] Decrypting {} messages...", self.encrypted_spool.len());
        let private_key = self.key_principal.get_private_key();
        for mime in self.encrypted_spool.drain(..) {
            let plain = mime.decrypt(private_key.clone());
            self.messages.push(plain);
        }
    }

    /// Full retrieval pipeline: connect -> authenticate -> fetch -> decrypt.
    /// This is the top-level jpgetmail operation.
    pub fn retrieve_messages(&mut self) {
        let socket = self.connect();
        let auth_ok = self.authenticate(&socket);
        if !auth_ok {
            println!("[POP3] Authentication FAILED -- aborting.");
            return;
        }
        self.fetch_encrypted_messages(&socket);
        self.decrypt_messages();
        socket.send_command("QUIT");
        println!("[POP3] Session closed.");
    }

    // ============================================================================
    // DISPLAY METHODS
    // ============================================================================

    /// Display message metadata (public headers only -- safe for anyone).
    pub fn display_headers(msg: &JPMailMessage) {
        println!("  From   : {}", msg.from);
        println!("  To     : {}", msg.to);
        println!("  Subject: {}", msg.subject);
    }

    /// Display the full message including the body.
    pub fn display_message(&self, msg: &JPMailMessage) {
        println!("  --- Message ---");
        Self::display_headers(msg);
        println!("  Body   : [requires authorized access]");
    }

    /// Display the body of a message publicly.
    pub fn display_body_publicly(msg: &JPMailMessage) {
        println!("  Body (public): {}", msg.body);
    }

    /// Count messages.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}
