// ============================================================================
// Mirrors: jpmail/src/pop3/MailReaderCrypto.jif
//
// Jif source (abridged):
//   class MailReaderCrypto[label L] {
//       // POP3 connection fields
//       String{} server;
//       String{L} username;         // labeled: the username is secret context
//       char{L}[] password;         // labeled: plaintext POP3 password
//       // POP3 socket (labeled L after authentication)
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
//   alice runs MailReaderCrypto<A>  → retrieves and decrypts Label-A mail
//   bono  runs MailReaderCrypto<Public> → retrieves public mail only
//   bono CANNOT decrypt or display alice's Label-A messages
// ============================================================================

pub mod content;
pub mod header;
pub mod message;
pub mod part;

use crate::crypto::{authorized_declassify, DeclassAuthorization};
use crate::net::SecureSocket;
use crate::password::Password;
use crate::policy::KeyPrincipal;
use crate::pop3::message::{JPMailMessage, MimeMailMessage};
use crate::smtp::auth::DigestApop;
use macros::mcall;
use typing_rules::lattice::*;

/// POP3 mail retrieval client with information flow control.
///
/// The type parameter L is the security clearance of the authenticated user:
///   - `MailReaderCrypto<A>`      for alice  — can decrypt Label-A messages
///   - `MailReaderCrypto<B>`      for bob    — can decrypt Label-B messages
///   - `MailReaderCrypto<Public>` for bono   — no access to labeled messages
///
/// In JPmail, MailReaderCrypto is invoked as jpsendmail:
///   make pop3/MailReaderCrypto ARGS='alice jpmail.cse.psu.edu alice'
pub struct MailReaderCrypto<L: Label> {
    /// POP3 server hostname (String{} in Jif — public, server address is not secret).
    pub server: String, // String{} server
    /// Raw principal name (public — used to create DeclassAuthorization tokens).
    /// In JPmail: this is the command-line argument (e.g. "alice").
    pub principal_name: String,
    /// Authenticated username (String{L} in Jif — ties this session to principal L).
    pub username: Labeled<String, L>, // String{L} username
    /// POP3 password (char{L}[] in Jif — secret credential).
    pub password: Labeled<String, L>, // char{L}[] password
    /// The key principal used to decrypt messages (private key is labeled L).
    pub key_principal: KeyPrincipal<L>,
    /// Retrieved and decrypted messages (labeled L — body content).
    pub messages: Vec<JPMailMessage<L>>,
    /// Raw encrypted messages from the server (still on-wire format).
    encrypted_spool: Vec<MimeMailMessage<L>>,
}

impl<L: Label> MailReaderCrypto<L> {
    /// Create a new mail reader.
    /// Mirrors: MailReaderCrypto constructor.
    ///
    /// `principal_name` is the raw principal identifier (e.g. "alice") — public
    /// metadata used for DeclassAuthorization and certificate lookup.
    pub fn new(server: &str, principal_name: &str, username: Labeled<String, L>, password: Labeled<String, L>) -> Self {
        let key_principal = KeyPrincipal::new(principal_name, &format!("demo/certs-{}/", principal_name), password.clone());
        MailReaderCrypto {
            server: server.to_string(),
            principal_name: principal_name.to_string(),
            username,
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    /// Load credentials from encrypted password files on disk.
    /// Mirrors: the password reading path in MailReaderCrypto.jif using Password.jif
    pub fn from_password_file(server: &str, username: &str, cert_dir: &str) -> Self {
        let username_labeled = Labeled::<String, L>::new(username.to_string());
        let pw_file = Password::<L>::new(&format!("demo/passwd-{}/", username));
        let password = pw_file.get_password();
        let key_principal = KeyPrincipal::new(username, cert_dir, password.clone());
        MailReaderCrypto {
            server: server.to_string(),
            principal_name: username.to_string(),
            username: username_labeled,
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    /// Open a POP3 connection.
    /// Mirrors: connect() in MailReaderCrypto.jif
    ///
    /// In JPmail: opens Socket[L]{L} to server:110 (or 995 for POP3S).
    /// The socket is labeled L — all responses carry the user's security level.
    pub fn connect(&self) -> SecureSocket<L> {
        println!("[POP3] Connecting to {}:110", self.server);
        let auth = DeclassAuthorization::new(&self.principal_name);
        let socket = authorized_declassify(SecureSocket::<L>::create(&self.server, 110), &auth);
        // Read server greeting (e.g. "+OK JPmail POP3 server ready")
        let greeting = authorized_declassify(socket.read_line(), &auth);
        println!("[POP3] Server: {}", greeting);
        socket
    }

    /// Authenticate with APOP or DIGEST-MD5.
    /// Mirrors: authenticate() in MailReaderCrypto.jif
    ///
    /// In JPmail: MailReaderCrypto sends "USER" + "PASS" or APOP.
    /// The password is labeled L — the APOP digest is labeled L too.
    ///
    /// Returns `Labeled<bool, L>` — whether auth succeeded, labeled L
    /// (even the success/failure of authentication is sensitive).
    pub fn authenticate(&self, socket: &SecureSocket<L>) -> Labeled<bool, L> {
        println!("[POP3] Authenticating (APOP)");
        // In JPmail: DigestMD5.getAPOPDigest(password, server_challenge)
        let apop_auth = DeclassAuthorization::new(&self.principal_name);
        let apop = DigestApop::new(self.password.clone());
        let challenge = socket.read_line(); // "+OK <timestamp@server>" challenge
        let digest = apop.compute_apop_digest(challenge, &apop_auth);

        // Send USER + APOP response (digest is labeled L — not printable publicly)
        let auth = DeclassAuthorization::new(&self.principal_name);
        let user_cmd = Labeled::<String, L>::new(format!("USER {}", authorized_declassify(self.username.clone(), &auth)));
        socket.write_line(user_cmd);
        // NOTE: `socket.write_line(digest)` would require L: FlowsTo<L>, which holds.
        // Sending the digest over a Public socket would require L: FlowsTo<Public> — DENIED.
        let _ = digest;

        let mut response = socket.read_line();
        mcall!(response.starts_with("+OK"))
    }

    /// Retrieve all messages from the server.
    /// Mirrors: getMessages() in MailReaderCrypto.jif
    ///
    /// In JPmail: issues "LIST", then "RETR n" for each message.
    /// Parses each response as MimeMailMessage[L] from a BufferedReader[L].
    ///
    /// Returns `Vec<MimeMailMessage<L>>` — the on-wire MIME format (encrypted).
    pub fn fetch_encrypted_messages(&mut self, socket: &SecureSocket<L>) {
        println!("[POP3] Fetching message list (LIST)...");
        socket.send_command("LIST");
        let list_response = socket.read_line();
        println!("[POP3] [labeled list response]");

        // In JPmail: iterates RETR 1, RETR 2, ... until no more messages
        // Stub: simulate two messages in alice's spool
        println!("[POP3] RETR 1");
        let raw = socket.read_line(); // labeled response
        let _ = raw;

        // Build stub encrypted message (in real impl: parsed from MIME stream)
        let crypto_info: Labeled<String, L> = Labeled::new("[rsa_wrapped_aes_key_stub]".to_string());
        let auth = DeclassAuthorization::new(&self.principal_name);
        let header = crate::pop3::header::MimeHeader::new(&authorized_declassify(self.username.clone(), &auth), "sender@example.com", "(encrypted subject stub)", crypto_info);
        let encrypted_body_bytes: Labeled<Vec<u8>, L> = Labeled::new(b"[encrypted_body_stub]".to_vec());
        let part = crate::pop3::part::MimePart::make_base64(encrypted_body_bytes, "body.enc");
        let mime_msg = MimeMailMessage { header, parts: vec![part] };
        self.encrypted_spool.push(mime_msg);
    }

    /// Decrypt all fetched messages using the owner's private key.
    /// Mirrors: the decryption loop in MailReaderCrypto.jif
    ///
    /// Requires the private key from the key principal (labeled L).
    /// Produces `Vec<JPMailMessage<L>>` — plaintext messages, still labeled L.
    ///
    /// IFC enforcement:
    ///   - Private key is `Labeled<String, L>` — only L-clearance code can supply it.
    ///   - Decrypted body is `Labeled<String, L>` — stays confined to L context.
    ///   - Bono (L=Public) calling this on Label-A spool messages is a TYPE ERROR:
    ///       his `KeyPrincipal<Public>` cannot produce a `Labeled<String, A>` key.
    pub fn decrypt_messages(&mut self) {
        println!("[POP3] Decrypting {} messages...", self.encrypted_spool.len());
        let auth = DeclassAuthorization::new(&self.principal_name);
        let private_key = self.key_principal.get_private_key();
        for mime in self.encrypted_spool.drain(..) {
            let plain = mime.decrypt(private_key.clone(), &auth);
            self.messages.push(plain);
        }
    }

    /// Full retrieval pipeline: connect → authenticate → fetch → decrypt.
    /// This is the top-level jpgetmail operation.
    pub fn retrieve_messages(&mut self) {
        let socket = self.connect();
        let auth_ok = self.authenticate(&socket);
        if auth_ok == false {
            println!("[POP3] Authentication FAILED — aborting.");
            return;
        }
        self.fetch_encrypted_messages(&socket);
        self.decrypt_messages();
        socket.send_command("QUIT");
        println!("[POP3] Session closed.");
    }

    // ============================================================================
    // DISPLAY METHODS — IFC ENFORCEMENT BOUNDARY
    // ============================================================================

    /// Display message metadata (public headers only — safe for anyone).
    /// from and subject are raw String; to is Labeled<String, L>.
    pub fn display_headers(msg: &JPMailMessage<L>) {
        println!("  From   : {}", msg.from); // String (raw)
        println!("  To     : [Labeled<String, L>]"); // labeled — not declassified
        println!("  Subject: {}", msg.subject); // String (raw)
    }

    /// Display the full message including the body.
    ///
    /// Because this function accesses `msg.body` (labeled L), it can only
    /// be called in a context that holds the `MailReaderCrypto<L>` object —
    /// i.e., code that already operates at clearance L.
    ///
    /// Bono (operating at Public) cannot call this on `JPMailMessage<A>`:
    ///   his reader is `MailReaderCrypto<Public>`, which only holds
    ///   `JPMailMessage<Public>` messages — type mismatch at compile time.
    pub fn display_message(&self, msg: &JPMailMessage<L>) {
        println!("  --- Message ---");
        Self::display_headers(msg);
        println!("  Body   : [Labeled<String, L> — requires authorized declassification]");
    }

    /// Display the body of a message in a PUBLIC context.
    ///
    /// The where-bound `L: FlowsTo<Public>` is the IFC enforcement point:
    ///   - Label Public: FlowsTo<Public> ✓ — public messages can be printed
    ///   - Label A:      A: FlowsTo<Public> ✗ — COMPILE ERROR for alice's mail
    ///   - Label B:      B: FlowsTo<Public> ✗ — COMPILE ERROR for bob's mail
    ///
    /// In JPmail: printing a labeled string to stdout requires a declassification
    /// closure (e.g., DeclassStringClosure) that the type-checker verifies.
    pub fn display_body_publicly(msg: &JPMailMessage<L>)
    where
        L: LEQ<Public>,
    {
        println!("  Body (public): {}", declassify(msg.body.clone()));
    }

    /// Count messages using mcall! to preserve the label.
    pub fn message_count(&self) -> Labeled<usize, L> {
        let mut msgs: Labeled<&Vec<JPMailMessage<L>>, L> = Labeled::new(&self.messages);
        mcall!(msgs.len())
    }
}
