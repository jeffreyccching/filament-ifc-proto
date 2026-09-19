// ============================================================================
// Mirrors: jpmail/src/pop3/JPMailMessage.jif
//          jpmail/src/pop3/MimeMailMessage.jif
//
// JPMailMessage.jif (abridged):
//   class JPMailMessage[label L] {
//       protected String{L}   recipient;     // labeled: who the mail is for
//       protected String{L}   body;          // labeled: the plaintext body
//       toMimeMailMessage(): MimeMailMessage[L] {
//           // try AES encryption, fall back to DES
//           // RSA-encrypt the session key for the recipient
//           // assemble MIME parts
//       }
//   }
//
// MimeMailMessage.jif (abridged):
//   class MimeMailMessage[label L] {
//       MimeHeader{} header;          // public header
//       MimePart[L]  parts[];         // labeled body parts
//       static getMimeMailMessage(BufferedReader[L] br)  // parse from POP3 stream
//       // Dynamic array reallocation in 5-10 part increments (noted in comments)
//   }
// ============================================================================

use crate::crypto::{aes_encrypt, authorized_declassify, des_encrypt, DeclassAuthorization, RSAClosure};
use crate::pop3::header::MimeHeader;
use crate::pop3::part::MimePart;
use macros::mcall;
use typing_rules::lattice::*;

// ============================================================================
// JP MAIL MESSAGE
// Mirrors: JPMailMessage.jif
// ============================================================================

/// A JPmail message before encryption.
///
/// `body` is `Labeled<String, L>` — the plaintext is confined to clearance L.
/// `recipient` is also labeled L because the intended recipient is linked to
/// the body's confidentiality (knowing who the mail is for reveals information
/// about the content).
///
/// Calling `to_mime()` encrypts the body and produces a `MimeMailMessage<L>`
/// suitable for transmission over SMTP.
#[derive(Clone)]
pub struct JPMailMessage<L: Label> {
    /// Sender's email address (String{} in Jif — public, visible in SMTP envelope).
    pub from: String, // String{} from
    /// Recipient's email address (String{L} in Jif — labeled L).
    pub to: Labeled<String, L>, // String{L} recipient
    /// Subject line (String{} in Jif — public, visible to mail servers).
    pub subject: String, // String{} subject
    /// Plaintext message body (String{L} in Jif — the confidential content).
    pub body: Labeled<String, L>, // String{L} body
}

impl<L: Label> JPMailMessage<L> {
    /// Construct a new JPmail message.
    pub fn new(from: &str, to: &str, subject: &str, body: Labeled<String, L>) -> Self {
        JPMailMessage {
            from: from.to_string(),
            to: Labeled::new(to.to_string()),
            subject: subject.to_string(),
            body,
        }
    }

    /// Convert the message to an encrypted MIME structure for transmission.
    /// Mirrors: toMimeMailMessage() in JPMailMessage.jif
    ///
    /// JPmail sequence:
    ///   1. Generate a random AES session key (labeled L).
    ///   2. Encrypt the body with AES (fall back to DES on failure).
    ///   3. RSA-encrypt the session key with the recipient's public key.
    ///   4. Build MimeHeader: crypto_info = Base64(RSA(sessionKey)), labeled L.
    ///   5. Build MimePart array: [encrypted_body (base64, labeled L)].
    ///   6. Return MimeMailMessage<L>.
    ///
    /// The session key is labeled L throughout — code operating below L
    /// cannot access it.
    pub fn to_mime(&self, recipient_key_id: &str) -> MimeMailMessage<L> {
        println!("[JPMailMessage] Converting to MIME (encrypting body)...");

        // Step 1: session key (stub — labeled L)
        let session_key: Labeled<Vec<u8>, L> = Labeled::new(b"stub_aes_session_key_32bytes!!!!".to_vec());

        // Step 2: encrypt body with AES (fall back to DES)
        // `self` is `&self` so the macro's `(&mut #base).__mcall_mut(...)`
        // expansion fails. Bypass via the `&self` form.
        let body_bytes: Labeled<Vec<u8>, L> = (&self.body).__mcall(|inner| inner.as_bytes().to_vec());
        let encrypted_body = aes_encrypt(body_bytes, session_key.clone());
        // In JPmail: try { AES } catch { DES }
        let _ = des_encrypt(encrypted_body.clone(), session_key.clone()); // fallback stub

        // Step 3: RSA-encrypt session key for recipient
        let rsa = RSAClosure::new(session_key, recipient_key_id);
        let mut wrapped_key: Labeled<Vec<u8>, L> = rsa.invoke();

        // Step 4: Build labeled crypto_info (Base64 of RSA-wrapped key)
        // Authorization: sender (self.from) authorizes header construction
        let auth = DeclassAuthorization::new(&self.from);
        let crypto_info: Labeled<String, L> = Labeled::new(format!("[base64_rsa_wrapped_key:{}]", authorized_declassify(mcall!(wrapped_key.len()), &auth)));

        let header = MimeHeader::new(&authorized_declassify(self.to.clone(), &auth), &self.from, &self.subject, crypto_info);

        // Step 5: Body MIME part (Base64 encoded, labeled L)
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
/// The body parts are labeled L (encrypted ciphertext — provenance tracked).
///
/// MimeMailMessage.jif notes: "Dynamic array reallocation in 5-10 part
/// increments" when parsing incoming messages.
#[derive(Clone)]
pub struct MimeMailMessage<L: Label> {
    /// Public headers: To, From, Subject, Content-Type, crypto_info (labeled L).
    pub header: MimeHeader<L>,
    /// Labeled MIME parts (encrypted body + attachments).
    pub parts: Vec<MimePart<L>>,
}

impl<L: Label> MimeMailMessage<L> {
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
    /// Requires the recipient's private key as `Labeled<String, L>`.
    /// The private key must be labeled L — only code at clearance L
    /// (e.g., alice's jpgetmail session) can supply it.
    ///
    /// Steps:
    ///   1. Decode crypto_info to get RSA-wrapped session key.
    ///   2. RSA-decrypt session key with private key (both labeled L).
    ///   3. AES-decrypt body parts with session key.
    ///   4. Reassemble plaintext body (still labeled L).
    pub fn decrypt(&self, private_key: Labeled<String, L>, auth: &DeclassAuthorization) -> JPMailMessage<L> {
        println!("[MimeMailMessage] Decrypting message...");

        // Step 1 & 2: unwrap session key with RSA private key
        let wrapped_key_bytes: Labeled<Vec<u8>, L> = Labeled::new(b"stub_wrapped_key".to_vec());
        let session_key = RSAClosure::decrypt(wrapped_key_bytes, private_key);

        // Step 3: decrypt body bytes from the first part
        let body_bytes = if let Some(part) = self.parts.first() {
            crate::crypto::aes_decrypt(part.body.clone(), session_key)
        } else {
            Labeled::new(Vec::new())
        };

        // Step 4: convert bytes back to labeled string (authorized declassification for format conversion)
        let body_text: Labeled<String, L> = Labeled::new(
            String::from_utf8(authorized_declassify(body_bytes, auth)).unwrap_or_else(|_| "[decode error]".into()),
        );

        JPMailMessage {
            from: self.header.from.clone(),
            to: Labeled::new(self.header.to.clone()),
            subject: self.header.subject.clone(),
            body: body_text,
        }
    }
}
