// ============================================================================
// Mirrors: jpmail/src/pop3/JPMailMessage.jif
//          jpmail/src/pop3/MimeMailMessage.jif
//
// JPMailMessage.jif (abridged):
//   class JPMailMessage[label L] {
//       protected String{L}   recipient;
//       protected String{L}   body;
//       toMimeMailMessage(): MimeMailMessage[L] { ... }
//   }
//
// MimeMailMessage.jif (abridged):
//   class MimeMailMessage[label L] {
//       MimeHeader{} header;
//       MimePart[L]  parts[];
//       static getMimeMailMessage(BufferedReader[L] br)
//   }
// ============================================================================

use crate::crypto::{aes_encrypt, des_encrypt, RSAClosure};
use crate::pop3::header::MimeHeader;
use crate::pop3::part::MimePart;

// ============================================================================
// JP MAIL MESSAGE
// Mirrors: JPMailMessage.jif
// ============================================================================

/// A JPmail message before encryption.
///
/// `body` is the plaintext.
/// `to` is the recipient address.
///
/// Calling `to_mime()` encrypts the body and produces a `MimeMailMessage`
/// suitable for transmission over SMTP.
#[derive(Clone)]
pub struct JPMailMessage {
    /// Sender's email address (public, visible in SMTP envelope).
    pub from: String,
    /// Recipient's email address.
    pub to: String,
    /// Subject line (public, visible to mail servers).
    pub subject: String,
    /// Plaintext message body (the confidential content).
    pub body: String,
}

impl JPMailMessage {
    /// Construct a new JPmail message.
    pub fn new(from: &str, to: &str, subject: &str, body: String) -> Self {
        JPMailMessage {
            from: from.to_string(),
            to: to.to_string(),
            subject: subject.to_string(),
            body,
        }
    }

    /// Convert the message to an encrypted MIME structure for transmission.
    /// Mirrors: toMimeMailMessage() in JPMailMessage.jif
    ///
    /// JPmail sequence:
    ///   1. Generate a random AES session key.
    ///   2. Encrypt the body with AES (fall back to DES on failure).
    ///   3. RSA-encrypt the session key with the recipient's public key.
    ///   4. Build MimeHeader: crypto_info = Base64(RSA(sessionKey)).
    ///   5. Build MimePart array: [encrypted_body (base64)].
    ///   6. Return MimeMailMessage.
    pub fn to_mime(&self, recipient_key_id: &str) -> MimeMailMessage {
        println!("[JPMailMessage] Converting to MIME (encrypting body)...");

        // Step 1: session key (stub)
        let session_key: Vec<u8> = b"stub_aes_session_key_32bytes!!!!".to_vec();

        // Step 2: encrypt body with AES (fall back to DES)
        let body_bytes: Vec<u8> = self.body.as_bytes().to_vec();
        let encrypted_body = aes_encrypt(body_bytes, session_key.clone());
        // In JPmail: try { AES } catch { DES }
        let _ = des_encrypt(encrypted_body.clone(), session_key.clone()); // fallback stub

        // Step 3: RSA-encrypt session key for recipient
        let rsa = RSAClosure::new(session_key, recipient_key_id);
        let wrapped_key: Vec<u8> = rsa.invoke();

        // Step 4: Build crypto_info (Base64 of RSA-wrapped key)
        let crypto_info: String = format!("[base64_rsa_wrapped_key:{}]", wrapped_key.len());

        let header = MimeHeader::new(&self.to, &self.from, &self.subject, crypto_info);

        // Step 5: Body MIME part (Base64 encoded)
        let body_part = MimePart::make_base64(encrypted_body, "body.enc");

        // Step 6: Assemble
        MimeMailMessage { header, parts: vec![body_part] }
    }
}

// ============================================================================
// MIME MAIL MESSAGE
// Mirrors: MimeMailMessage.jif
// ============================================================================

/// An assembled, encrypted MIME message ready for SMTP transmission.
///
/// Mirrors: MimeMailMessage[label L] in MimeMailMessage.jif
///
/// The header is public (SMTP relays can read To/From/Subject).
/// The body parts contain encrypted ciphertext.
///
/// MimeMailMessage.jif notes: "Dynamic array reallocation in 5-10 part
/// increments" when parsing incoming messages.
#[derive(Clone)]
pub struct MimeMailMessage {
    /// Public headers: To, From, Subject, Content-Type, crypto_info.
    pub header: MimeHeader,
    /// MIME parts (encrypted body + attachments).
    pub parts: Vec<MimePart>,
}

impl MimeMailMessage {
    /// Serialize the public headers (safe to log / display to anyone).
    pub fn show_public_headers(&self) {
        println!("  From   : {}", self.header.from);
        println!("  To     : {}", self.header.to);
        println!("  Subject: {}", self.header.subject);
        println!("  MIME-Version: {}", self.header.mime_version);
    }

    /// Decrypt and recover the plaintext JPMailMessage.
    /// Mirrors: the decryption path in MailReaderCrypto.jif
    ///
    /// Requires the recipient's private key.
    ///
    /// Steps:
    ///   1. Decode crypto_info to get RSA-wrapped session key.
    ///   2. RSA-decrypt session key with private key.
    ///   3. AES-decrypt body parts with session key.
    ///   4. Reassemble plaintext body.
    pub fn decrypt(&self, private_key: String) -> JPMailMessage {
        println!("[MimeMailMessage] Decrypting message...");

        // Step 1 & 2: unwrap session key with RSA private key
        let wrapped_key_bytes: Vec<u8> = b"stub_wrapped_key".to_vec();
        let session_key = RSAClosure::decrypt(wrapped_key_bytes, private_key);

        // Step 3: decrypt body bytes from the first part
        let body_bytes = if let Some(part) = self.parts.first() {
            crate::crypto::aes_decrypt(part.body.clone(), session_key)
        } else {
            Vec::new()
        };

        // Step 4: convert bytes back to string
        let body_text: String =
            String::from_utf8(body_bytes).unwrap_or_else(|_| "[decode error]".into());

        JPMailMessage {
            from: self.header.from.clone(),
            to: self.header.to.clone(),
            subject: self.header.subject.clone(),
            body: body_text,
        }
    }
}
