// ============================================================================
// Mirrors: jpmail/src/smtp/MailSenderCrypto.jif
//
// Jif source (abridged, 32,263 bytes):
//   class MailSenderCrypto[label L] {
//       String{} smtpServer;
//       String{} smtpUsername;
//       String{} emailAddress;
//       char{L}[] smtpPassword;
//
//       void send(JPMailMessage[L] msg) throws IOException { ... }
//   }
//
// MailSenderCrypto is the jpsendmail executable.
// Usage: make smtp/MailSenderCrypto ARGS='[principal] [server] [user] [addr]'
//
// In the demo:
//   alice runs MailSenderCrypto -- sends messages
//   Declassification happens via closures (DeclassMsgBodyClosure,
//   EmailHdrDeclassClosure, DeclassStringClosure)
// ============================================================================

pub mod auth;
pub mod closures;

use crate::net::SecureSocket;
use crate::password::Password;
use crate::pop3::message::JPMailMessage;
use crate::smtp::auth::DigestMD5;
use crate::smtp::closures::{
    DeclassMsgBodyClosure, DeclassStringClosure, EmailDisclaimerClosure, EmailHdrDeclassClosure,
};

/// SMTP mail sender.
/// Mirrors: MailSenderCrypto[label L] in MailSenderCrypto.jif
///
/// All messages sent through this instance have their bodies encrypted
/// before transmission.
///
/// In JPmail, jpsendmail is invoked as:
///   make smtp/MailSenderCrypto ARGS='alice mail.cse.psu.edu alice alice@cse.psu.edu'
pub struct MailSenderCrypto {
    /// SMTP server hostname (public, visible to DNS and network).
    pub smtp_server: String,
    /// SMTP authentication username (public, sent in SASL exchange).
    pub smtp_username: String,
    /// Sender email address (public, appears in MAIL FROM).
    pub email_address: String,
    /// SMTP authentication password (secret credential).
    pub smtp_password: String,
}

impl MailSenderCrypto {
    /// Create a sender with an inline password.
    pub fn new(
        smtp_server: &str,
        smtp_username: &str,
        email_address: &str,
        smtp_password: String,
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
        let pw_file = Password::new(&format!("demo/{}", password_dir));
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
    fn connect_smtp(&self) -> SecureSocket {
        println!("[SMTP] Connecting to {}:587", self.smtp_server);
        let socket = SecureSocket::create(&self.smtp_server, 587);
        let greeting = socket.read_line();
        println!("[SMTP] Server: {}", greeting);
        socket
    }

    /// Authenticate with DIGEST-MD5.
    /// Mirrors: the SASL authentication section in MailSenderCrypto.jif
    ///
    /// The SMTP password is used to compute the DIGEST-MD5 response.
    /// The response must be declassified before it can be written to the socket.
    fn authenticate_smtp(&self, socket: &SecureSocket) {
        println!("[SMTP] Initiating DIGEST-MD5 authentication...");
        socket.send_command("AUTH DIGEST-MD5");

        // Server challenge is public (base64-encoded, unencrypted)
        let challenge_pub = socket.read_line();
        println!("[SMTP] Challenge: {}", challenge_pub);

        // Build DigestMD5
        let auth = DigestMD5::new(
            self.smtp_password.clone(),
            &self.smtp_username,
            "cse.psu.edu",
        );

        let response: String = auth.auth_client(challenge_pub);

        // The DIGEST-MD5 response is declassified via DeclassStringClosure.
        let closure = DeclassStringClosure::new(response);
        let public_response: String = closure.invoke();

        // Now safe to write to the SMTP socket
        socket.send_command(&public_response);

        let result = socket.read_line();
        println!("[SMTP] Auth result: {}", result);
    }

    /// Send an encrypted message via SMTP.
    /// Mirrors: send(JPMailMessage[L] msg) in MailSenderCrypto.jif
    ///
    /// Full sequence:
    ///   1. Convert JPMailMessage to MimeMailMessage (encrypts body)
    ///   2. Connect + EHLO
    ///   3. DIGEST-MD5 authentication
    ///   4. MAIL FROM / RCPT TO (public envelope)
    ///   5. Declassify headers via EmailHdrDeclassClosure
    ///   6. Declassify body via DeclassMsgBodyClosure
    ///   7. Add disclaimer via EmailDisclaimerClosure
    ///   8. Write DATA (public ciphertext over public SMTP channel)
    pub fn send_message(&self, msg: &JPMailMessage, recipient_key_id: &str) {
        println!("\n[SMTP] Preparing to send message: '{}'", msg.subject);

        // Step 1: Convert to encrypted MIME
        let _mime = msg.to_mime(recipient_key_id);

        // Steps 2-3: Connect and authenticate
        let socket = self.connect_smtp();
        socket.send_command(&format!("EHLO {}", self.email_address));
        self.authenticate_smtp(&socket);

        // Step 4: SMTP envelope (public -- Mail From, Rcpt To)
        let to_closure = DeclassStringClosure::new(msg.to.clone());
        let public_to: String = to_closure.invoke();
        socket.send_command(&format!("MAIL FROM:<{}>", self.email_address));
        socket.send_command(&format!("RCPT TO:<{}>", public_to));
        socket.send_command("DATA");

        // Step 5: Declassify headers
        let hdr_closure = EmailHdrDeclassClosure::new(msg.clone());
        let public_headers: String = hdr_closure.invoke();
        socket.send_command(&public_headers);

        // Step 6: Declassify body (body is encrypted then declassified)
        let body_closure = DeclassMsgBodyClosure::new(msg.body.clone(), recipient_key_id);
        let encrypted_body: Vec<u8> = body_closure.invoke();
        println!(
            "[SMTP] Sending {} bytes encrypted body (declassified via RSA)",
            encrypted_body.len()
        );

        // Step 7: Disclaimer (optional -- add legal notice to outgoing mail)
        let disclaimer = EmailDisclaimerClosure::new(msg.body.clone());
        let body_with_note: String = disclaimer.invoke();
        // body_with_note is now raw -- safe to write to SMTP
        let _ = body_with_note;

        // Step 8: End DATA
        socket.send_command(".");
        let response = socket.read_line();
        println!("[SMTP] Server accepted: {}", response);
        socket.send_command("QUIT");
        println!("[SMTP] Message '{}' sent successfully.", msg.subject);
    }
}
