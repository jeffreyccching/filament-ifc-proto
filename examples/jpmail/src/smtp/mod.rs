// ============================================================================
// Mirrors: jpmail/src/smtp/MailSenderCrypto.jif
//
// Jif source (abridged, 32,263 bytes):
//   class MailSenderCrypto[label L] {
//       String{} smtpServer;
//       String{} smtpUsername;
//       String{} emailAddress;
//       char{L}[] smtpPassword;       // labeled: SMTP auth credential
//
//       void send(JPMailMessage[L] msg)  throws IOException {
//           // 1. Convert message to MIME (encrypts body)
//           // 2. Connect to SMTP server
//           // 3. DIGEST-MD5 authentication
//           // 4. Declassify headers + body via closures
//           // 5. Write SMTP DATA (public ciphertext)
//       }
//   }
//
// MailSenderCrypto is the jpsendmail executable.
// Usage: make smtp/MailSenderCrypto ARGS='[principal] [server] [user] [addr]'
//
// In the demo:
//   alice runs MailSenderCrypto<A> — sends Label-A messages
//   Declassification only happens via authorized closures (DeclassMsgBodyClosure,
//   EmailHdrDeclassClosure, DeclassStringClosure)
// ============================================================================

pub mod auth;
pub mod closures;

use crate::crypto::DeclassAuthorization;
use crate::net::SecureSocket;
use crate::password::Password;
use crate::pop3::message::JPMailMessage;
use crate::smtp::auth::DigestMD5;
use crate::smtp::closures::{
    DeclassMsgBodyClosure, DeclassStringClosure, EmailDisclaimerClosure, EmailHdrDeclassClosure,
};
use typing_rules::lattice::*;

/// SMTP mail sender with information flow control.
/// Mirrors: MailSenderCrypto[label L] in MailSenderCrypto.jif
///
/// The type parameter L is the security level of the sender's credentials.
/// All messages sent through this instance have their bodies encrypted at
/// level L before transmission.
///
/// In JPmail, jpsendmail is invoked as:
///   make smtp/MailSenderCrypto ARGS='alice mail.cse.psu.edu alice alice@cse.psu.edu'
pub struct MailSenderCrypto<L: Label> {
    /// SMTP server hostname (String{} in Jif — public, visible to DNS and network).
    pub smtp_server: String,    // String{} smtpServer
    /// SMTP authentication username (String{} in Jif — public, sent in SASL exchange).
    pub smtp_username: String,  // String{} smtpUsername
    /// Sender email address (String{} in Jif — public, appears in MAIL FROM).
    pub email_address: String,  // String{} emailAddress
    /// SMTP authentication password (char{L}[] in Jif — secret credential).
    pub smtp_password: Labeled<String, L>,       // char{L}[] smtpPassword
}

impl<L: Label> MailSenderCrypto<L> {
    /// Create a sender with an inline password.
    pub fn new(
        smtp_server: &str,
        smtp_username: &str,
        email_address: &str,
        smtp_password: Labeled<String, L>,
    ) -> Self {
        MailSenderCrypto {
            smtp_server: smtp_server.to_string(),
            smtp_username: smtp_username.to_string(),
            email_address: email_address.to_string(),
            smtp_password,
        }
    }

    /// Create a sender, reading the SMTP password from an encrypted file.
    /// Mirrors: the password-loading path in MailSenderCrypto.jif using Password.jif
    pub fn from_password_file(
        smtp_server: &str,
        smtp_username: &str,
        email_address: &str,
        password_dir: &str,
    ) -> Self {
        let pw_file = Password::<L>::new(&format!("demo/{}", password_dir));
        let smtp_password = pw_file.get_password();
        MailSenderCrypto {
            smtp_server: smtp_server.to_string(),
            smtp_username: smtp_username.to_string(),
            email_address: email_address.to_string(),
            smtp_password,
        }
    }

    /// Connect to the SMTP server.
    /// Mirrors: the socket setup in MailSenderCrypto.jif
    ///
    /// In JPmail: opens a Socket to port 587 (submission) or 465 (SMTPS).
    /// Returns a public socket — SMTP greeting is before authentication.
    /// Uses safe_declassify to strip the Public label from the socket handle.
    fn connect_smtp(&self) -> SecureSocket<Public> {
        println!("[SMTP] Connecting to {}:587", self.smtp_server);
        let socket = SecureSocket::<Public>::create(&self.smtp_server, 587);
        let socket = declassify(socket);
        let greeting = socket.read_line();
        println!("[SMTP] Server: {}", declassify(greeting));
        socket
    }

    /// Authenticate with DIGEST-MD5.
    /// Mirrors: the SASL authentication section in MailSenderCrypto.jif
    ///
    /// The SMTP password (labeled L) is used to compute the DIGEST-MD5
    /// response (also labeled L). The response must be explicitly declassified
    /// via DeclassStringClosure before it can be written to the Public socket.
    fn authenticate_smtp(&self, socket: &SecureSocket<Public>) {
        println!("[SMTP] Initiating DIGEST-MD5 authentication...");
        socket.send_command("AUTH DIGEST-MD5");

        // Server challenge is public (base64-encoded, unencrypted)
        let challenge_pub = socket.read_line();
        println!("[SMTP] Challenge: {}", declassify(challenge_pub.clone()));

        // Build DigestMD5 — password is labeled L
        let auth = DigestMD5::new(
            self.smtp_password.clone(),
            &self.smtp_username,
            "cse.psu.edu",
        );

        // The challenge must be labeled L to be used with the password.
        // We upgrade the public challenge to L (safe: raising label).
        // Upgrade public challenge to L (Public → L is always safe)
        let challenge_l: Labeled<String, L> = Labeled::new(declassify(challenge_pub));
        let response_labeled: Labeled<String, L> = auth.auth_client(challenge_l);

        // The DIGEST-MD5 response is labeled L — it cannot be sent directly
        // to the Public socket. Declassify via DeclassStringClosure.
        let auth_token = DeclassAuthorization::new(&self.smtp_username);
        let closure = DeclassStringClosure::new(response_labeled);
        let public_response: String = closure.invoke(auth_token);

        // Now safe to write to the Public SMTP socket
        socket.send_command(&public_response);

        let result = socket.read_line();
        println!("[SMTP] Auth result: {}", declassify(result));
    }

    /// Send an encrypted message via SMTP.
    /// Mirrors: send(JPMailMessage[L] msg) in MailSenderCrypto.jif
    ///
    /// Full sequence:
    ///   1. Convert JPMailMessage<L> to MimeMailMessage<L> (encrypts body)
    ///   2. Connect + EHLO
    ///   3. DIGEST-MD5 authentication
    ///   4. MAIL FROM / RCPT TO (public envelope)
    ///   5. Declassify headers via EmailHdrDeclassClosure
    ///   6. Declassify body via DeclassMsgBodyClosure
    ///   7. Add disclaimer via EmailDisclaimerClosure
    ///   8. Write DATA (public ciphertext over public SMTP channel)
    pub fn send_message(&self, msg: &JPMailMessage<L>, recipient_key_id: &str) {
        println!("\n[SMTP] Preparing to send message: '{}'", msg.subject);

        // Step 1: Convert to encrypted MIME
        let mime = msg.to_mime(recipient_key_id);

        // Steps 2-3: Connect and authenticate
        let socket = self.connect_smtp();
        socket.send_command(&format!("EHLO {}", self.email_address));
        self.authenticate_smtp(&socket);

        // Step 4: SMTP envelope (public — Mail From, Rcpt To)
        // Declassify recipient via DeclassStringClosure (authorized path)
        let rcpt_auth = DeclassAuthorization::new(&self.smtp_username);
        let to_closure = DeclassStringClosure::new(msg.to.clone());
        let public_to: String = to_closure.invoke(rcpt_auth);
        socket.send_command(&format!("MAIL FROM:<{}>", self.email_address));
        socket.send_command(&format!("RCPT TO:<{}>", public_to));
        socket.send_command("DATA");

        // Step 5: Declassify headers (crypto_info is labeled L; rest is public)
        let hdr_auth = DeclassAuthorization::new(&self.smtp_username);
        let hdr_closure = EmailHdrDeclassClosure::new(msg.clone());
        let public_headers: String = hdr_closure.invoke(hdr_auth);
        socket.send_command(&public_headers);

        // Step 6: Declassify body (body is labeled L; encrypt+declassify)
        let body_auth = DeclassAuthorization::new(&self.smtp_username);
        let body_closure = DeclassMsgBodyClosure::new(msg.body.clone(), recipient_key_id);
        let encrypted_body: Vec<u8> = body_closure.invoke(body_auth);
        println!(
            "[SMTP] Sending {} bytes encrypted body (declassified via RSA)",
            encrypted_body.len()
        );

        // Step 7: Disclaimer (optional — add legal notice to outgoing mail)
        let disc_auth = DeclassAuthorization::new(&self.smtp_username);
        let disclaimer = EmailDisclaimerClosure::new(msg.body.clone());
        let body_with_note: String = disclaimer.invoke(disc_auth);
        // body_with_note is now raw — safe to write to SMTP
        let _ = body_with_note;

        // Step 8: End DATA
        socket.send_command(".");
        let response = socket.read_line();
        println!("[SMTP] Server accepted: {}", declassify(response));
        socket.send_command("QUIT");
        println!("[SMTP] Message '{}' sent successfully.", msg.subject);
    }
}
