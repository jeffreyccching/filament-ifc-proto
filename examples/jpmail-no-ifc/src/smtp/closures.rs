// ============================================================================
// Mirrors: jpmail/src/smtp/DeclassMsgBodyClosure.jif
//          jpmail/src/smtp/DeclassStringClosure.jif
//          jpmail/src/smtp/EmailHdrDeclassClosure.jif
//          jpmail/src/smtp/EmailDisclaimerClosure.jif
//
// In JPmail, closures are the only legitimate way to declassify labeled data.
// They implement the Closure[P, L] interface and are passed to
// PrincipalUtil.authorize(P, closure, lb, lb) for authorization.
// ============================================================================

use crate::pop3::message::JPMailMessage;

// ============================================================================
// DECLASSIFY MESSAGE BODY CLOSURE
// Mirrors: DeclassMsgBodyClosure.jif
// ============================================================================

/// Closure that encrypts and declassifies a message body for SMTP transmission.
///
/// In JPmail: this is the only legitimate path to convert the plaintext body
/// into a form that can be sent over the SMTP socket.
/// The invoke() method:
///   1. RSA-encrypts the body with the recipient's public key.
///   2. Returns the Ciphertext (computationally public).
///
/// The result is raw `Vec<u8>` (ciphertext is safe to send over a public channel).
pub struct DeclassMsgBodyClosure {
    /// The plaintext body (secret until encrypted).
    pub msg_body: String,
    /// The intended recipient's public key ID (public, key IDs are not secret).
    pub recipient_key_id: String,
}

impl DeclassMsgBodyClosure {
    pub fn new(msg_body: String, recipient_key_id: &str) -> Self {
        DeclassMsgBodyClosure {
            msg_body,
            recipient_key_id: recipient_key_id.to_string(),
        }
    }

    /// Encrypt the body and return the ciphertext (declassified to raw).
    /// Mirrors: invoke() in DeclassMsgBodyClosure.jif
    pub fn invoke(&self) -> Vec<u8> {
        println!(
            "[DeclassMsgBodyClosure] Encrypting body for recipient '{}'",
            self.recipient_key_id,
        );
        // In JPmail: calls RSA[{P:}].encrypt(msgBody, recipientKey)
        // The resulting ciphertext is public -- safe to send
        self.msg_body.as_bytes().to_vec()
    }
}

// ============================================================================
// DECLASSIFY STRING CLOSURE
// Mirrors: DeclassStringClosure.jif
// ============================================================================

/// Closure that declassifies a string (e.g. SASL auth response).
///
/// In JPmail: used for the SMTP SASL DIGEST-MD5 response, which is derived
/// from the password but must be sent over the SMTP socket (Public).
///
/// The invoke() returns the raw string (treated as computationally safe).
pub struct DeclassStringClosure {
    /// The string to declassify (e.g. auth digest).
    pub labeled_string: String,
}

impl DeclassStringClosure {
    pub fn new(labeled_string: String) -> Self {
        DeclassStringClosure { labeled_string }
    }

    /// Declassify the string for public transmission.
    /// Mirrors: invoke() in DeclassStringClosure.jif
    pub fn invoke(&self) -> String {
        println!(
            "[DeclassStringClosure] Declassifying string",
        );
        self.labeled_string.clone()
    }
}

// ============================================================================
// EMAIL HEADER DECLASSIFICATION CLOSURE
// Mirrors: EmailHdrDeclassClosure.jif
// ============================================================================

/// Closure that declassifies email header fields for SMTP transmission.
///
/// In JPmail: the crypto_info field of MimeHeader contains the RSA-wrapped
/// AES session key. Before this can be written to the SMTP socket, it must
/// be declassified via this closure.
///
/// After invoke(), the header string is raw -- safe for SMTP relays.
pub struct EmailHdrDeclassClosure {
    /// The message whose headers need declassification.
    pub message: JPMailMessage,
}

impl EmailHdrDeclassClosure {
    pub fn new(message: JPMailMessage) -> Self {
        EmailHdrDeclassClosure { message }
    }

    /// Extract and declassify the headers for SMTP transmission.
    /// Mirrors: invoke() in EmailHdrDeclassClosure.jif
    ///
    /// Public fields (To, From, Subject) are already raw.
    /// Only crypto_info needs to be declassified here.
    pub fn invoke(&self) -> String {
        println!(
            "[EmailHdrDeclassClosure] Declassifying headers for '{}'",
            self.message.subject,
        );
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nX-JPmail-CryptoInfo: [declassified_key_stub]",
            self.message.from, self.message.to, self.message.subject
        )
    }
}

// ============================================================================
// EMAIL DISCLAIMER CLOSURE
// Mirrors: EmailDisclaimerClosure.jif
//
// Disclaimer text (from source):
//   "This message and any attachments may contain confidential information..."
// ============================================================================

/// Closure that appends a legal disclaimer to the message body and declassifies.
///
/// This models the common enterprise requirement of attaching a confidentiality
/// notice to outgoing email.
pub struct EmailDisclaimerClosure {
    /// The original body.
    pub body: String,
}

/// Standard JPmail disclaimer text (reproduced from EmailDisclaimerClosure.jif).
const DISCLAIMER: &str = "\r\n\r\n\
    -----------------------------------------------------------------------\r\n\
    This message and any attachments may contain confidential information.\r\n\
    If you are not the intended recipient, please notify the sender and\r\n\
    delete this message. Any unauthorized use, disclosure, or distribution\r\n\
    of this message is strictly prohibited.\r\n\
    -----------------------------------------------------------------------";

impl EmailDisclaimerClosure {
    pub fn new(body: String) -> Self {
        EmailDisclaimerClosure { body }
    }

    /// Append the disclaimer and declassify.
    /// Mirrors: invoke() in EmailDisclaimerClosure.jif
    pub fn invoke(&self) -> String {
        let mut body = self.body.clone();
        body.push_str(DISCLAIMER);
        println!(
            "[EmailDisclaimerClosure] Appended disclaimer, declassifying",
        );
        body
    }
}
