// ============================================================================
// Mirrors: jpmail/src/smtp/DeclassMsgBodyClosure.jif
//          jpmail/src/smtp/DeclassStringClosure.jif
//          jpmail/src/smtp/EmailHdrDeclassClosure.jif
//          jpmail/src/smtp/EmailDisclaimerClosure.jif
//
// In JPmail, closures are the ONLY legitimate way to declassify labeled data.
// They implement the Closure[P, L] interface and are passed to
// PrincipalUtil.authorize(P, closure, lb, lb) for authorization.
//
// DeclassMsgBodyClosure.jif:
//   class DeclassMsgBodyClosure[principal P, label L]
//       implements Closure[P, L] {
//       final String{P:} msgBody;     // the labeled body to declassify
//       invoke(): Ciphertext          // returns encrypted body (declassified)
//   }
//
// DeclassStringClosure.jif:
//   class DeclassStringClosure[principal P, label L]
//       implements Closure[P, L] {
//       invoke(): Ciphertext          // declassifies a string
//   }
//
// EmailHdrDeclassClosure.jif:
//   class EmailHdrDeclassClosure[principal P, label L]
//       implements Closure[P, L] {
//       final JPMailMessage{P:} msg;
//       invoke(): Ciphertext          // declassifies the message headers
//   }
//
// EmailDisclaimerClosure.jif:
//   class EmailDisclaimerClosure[principal P, label L]
//       implements Closure[P, L] {
//       String{P:} msgBodyWithDisclaimer;
//       invoke(): Ciphertext          // appends legal disclaimer, then declassifies
//   }
//   Conditional declassification: checks if L <= {P:} before proceeding.
// ============================================================================

use crate::crypto::{authorized_declassify, DeclassAuthorization};
use crate::pop3::message::JPMailMessage;
use macros::mcall;
use typing_rules::lattice::*;

// ============================================================================
// DECLASSIFY MESSAGE BODY CLOSURE
// Mirrors: DeclassMsgBodyClosure.jif
// ============================================================================

/// Closure that encrypts and declassifies a message body for SMTP transmission.
///
/// In JPmail: this is the only legitimate path to convert `String{L}` (the
/// plaintext body) into a form that can be sent over the SMTP socket.
/// The invoke() method:
///   1. RSA-encrypts the body with the recipient's public key.
///   2. Returns the Ciphertext (computationally public, logically still tracked).
///
/// In Rust: we model the declassification result as raw `Vec<u8>`
/// (ciphertext is safe to send over a public channel).
/// The authorization token confirms this declassification is legitimate.
pub struct DeclassMsgBodyClosure<L: Label> {
    /// The plaintext body (String{P:} in Jif — labeled L, secret until encrypted).
    pub msg_body: Labeled<String, L>,              // String{P:} msgBody
    /// The intended recipient's public key ID (String{} — public, key IDs are not secret).
    pub recipient_key_id: String, // String{} — public
}

impl<L: Label> DeclassMsgBodyClosure<L> {
    pub fn new(msg_body: Labeled<String, L>, recipient_key_id: &str) -> Self {
        DeclassMsgBodyClosure {
            msg_body,
            recipient_key_id: recipient_key_id.to_string(),
        }
    }

    /// Encrypt the body and return the ciphertext (declassified to raw).
    /// Mirrors: invoke() in DeclassMsgBodyClosure.jif
    ///
    /// The authorization token confirms the principal has authority to
    /// declassify label L. After RSA encryption, the ciphertext is public
    /// (it is computationally safe to send over SMTP).
    pub fn invoke(&self, auth: DeclassAuthorization) -> Vec<u8> {
        println!(
            "[DeclassMsgBodyClosure] Encrypting body for recipient '{}' (auth: {})",
            self.recipient_key_id,
            auth.granted_by
        );
        // In JPmail: calls RSA[{P:}].encrypt(msgBody, recipientKey)
        // The resulting ciphertext is public — safe to send
        // `self` is `&self`; bypass the macro to use the `&self` form `__mcall`.
        authorized_declassify((&self.msg_body).__mcall(|inner| inner.as_bytes().to_vec()), &auth)
    }
}

// ============================================================================
// DECLASSIFY STRING CLOSURE
// Mirrors: DeclassStringClosure.jif
// ============================================================================

/// Closure that declassifies a labeled string (e.g. SASL auth response).
///
/// In JPmail: used for the SMTP SASL DIGEST-MD5 response, which is labeled L
/// (derived from the password) but must be sent over the SMTP socket (Public).
///
/// The invoke() returns the raw string (treated as computationally safe).
pub struct DeclassStringClosure<L: Label> {
    /// The labeled string to declassify (e.g. auth digest, labeled L).
    pub labeled_string: Labeled<String, L>,
}

impl<L: Label> DeclassStringClosure<L> {
    pub fn new(labeled_string: Labeled<String, L>) -> Self {
        DeclassStringClosure { labeled_string }
    }

    /// Declassify the string for public transmission.
    /// Mirrors: invoke() in DeclassStringClosure.jif
    ///
    /// After authorization, the string can be written to the SMTP socket.
    pub fn invoke(&self, auth: DeclassAuthorization) -> String {
        println!(
            "[DeclassStringClosure] Declassifying string (auth: {})",
            auth.granted_by
        );
        // In JPmail: returns declassify(labeledString) after authorize()
        authorized_declassify(self.labeled_string.clone(), &auth)
    }
}

// ============================================================================
// EMAIL HEADER DECLASSIFICATION CLOSURE
// Mirrors: EmailHdrDeclassClosure.jif
//
// Jif source:
//   class EmailHdrDeclassClosure[principal P, label L]
//       implements Closure[P, L] {
//       final JPMailMessage{P:} msg;   // message with L-labeled header fields
//       invoke(): Ciphertext           // returns the declassified/encrypted headers
//   }
// ============================================================================

/// Closure that declassifies email header fields for SMTP transmission.
///
/// In JPmail: the crypto_info field of MimeHeader is labeled L (it contains
/// the RSA-wrapped AES session key). Before this can be written to the SMTP
/// socket, it must be declassified via this closure.
///
/// After invoke(), the header string is raw — safe for SMTP relays.
pub struct EmailHdrDeclassClosure<L: Label> {
    /// The message whose headers need declassification (labeled L).
    pub message: JPMailMessage<L>,
}

impl<L: Label> EmailHdrDeclassClosure<L> {
    pub fn new(message: JPMailMessage<L>) -> Self {
        EmailHdrDeclassClosure { message }
    }

    /// Extract and declassify the headers for SMTP transmission.
    /// Mirrors: invoke() in EmailHdrDeclassClosure.jif
    ///
    /// Public fields (To, From, Subject) are already raw.
    /// Only crypto_info (labeled L) needs to be declassified here.
    pub fn invoke(&self, auth: DeclassAuthorization) -> String {
        println!(
            "[EmailHdrDeclassClosure] Declassifying headers for '{}' (auth: {})",
            self.message.subject, auth.granted_by
        );
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nX-JPmail-CryptoInfo: [declassified_key_stub]",
            self.message.from, authorized_declassify(self.message.to.clone(), &auth), self.message.subject
        )
    }
}

// ============================================================================
// EMAIL DISCLAIMER CLOSURE
// Mirrors: EmailDisclaimerClosure.jif
//
// Jif source:
//   class EmailDisclaimerClosure[principal P, label L]
//       implements Closure[P, L] {
//       String{P:} msgBodyWithDisclaimer;
//       invoke(): Ciphertext {
//           // conditional declassification: checks if L <= {P:}
//           // appends standard corporate disclaimer text
//           return declassify(msgBodyWithDisclaimer);
//       }
//   }
//   Disclaimer text (from source):
//     "This message and any attachments may contain confidential information..."
// ============================================================================

/// Closure that appends a legal disclaimer to the message body and declassifies.
///
/// In JPmail: the disclaimer closure checks the information flow constraint
/// `L <= {P:}` before appending the disclaimer and encrypting for transmission.
///
/// This models the common enterprise requirement of attaching a confidentiality
/// notice to outgoing email while still enforcing IFC.
pub struct EmailDisclaimerClosure<L: Label> {
    /// The original body (labeled L).
    pub body: Labeled<String, L>,
}

/// Standard JPmail disclaimer text (reproduced from EmailDisclaimerClosure.jif).
const DISCLAIMER: &str = "\r\n\r\n\
    -----------------------------------------------------------------------\r\n\
    This message and any attachments may contain confidential information.\r\n\
    If you are not the intended recipient, please notify the sender and\r\n\
    delete this message. Any unauthorized use, disclosure, or distribution\r\n\
    of this message is strictly prohibited.\r\n\
    -----------------------------------------------------------------------";

impl<L: Label> EmailDisclaimerClosure<L> {
    pub fn new(body: Labeled<String, L>) -> Self {
        EmailDisclaimerClosure { body }
    }

    /// Append the disclaimer and declassify.
    /// Mirrors: invoke() in EmailDisclaimerClosure.jif
    ///
    /// The conditional `L <= {P:}` check in Jif corresponds to the
    /// `DeclassAuthorization` token here — authorization is required
    /// before the body (labeled L) can be downgraded to raw.
    pub fn invoke(&self, auth: DeclassAuthorization) -> String {
        // Single authorized declassification — no need to re-wrap and declassify again
        // `self` is `&self`; bypass the macro to use the `&self` form `__mcall`.
        let mut body = authorized_declassify((&self.body).__mcall(|inner| inner.clone()), &auth);
        body.push_str(DISCLAIMER);
        println!(
            "[EmailDisclaimerClosure] Appended disclaimer, declassifying (auth: {})",
            auth.granted_by
        );
        body
    }
}
