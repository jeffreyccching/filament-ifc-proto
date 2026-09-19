// ============================================================================
// Mirrors: jpmail/src/pop3/MimeHeader.jif
//
// Jif source (abridged):
//   class MimeHeader[label L] {
//       protected String{} to;
//       protected String{} from;
//       protected String{} date;
//       protected String{} subject;
//       protected String{} contentType;
//       protected String{} mimeVersion;
//       protected String{L} cryptoInfo;   // encrypted key info
//
//       static MimeHeader getMimeHeader(BufferedReader[L] br, label L)
//       String generateBoundary()
//   }
//
// Note: six of the seven fields are public; only cryptoInfo was labeled L.
// cryptoInfo carries the RSA-encrypted AES session key.
// ============================================================================

use crate::pop3::content::ContentType;

/// MIME message header with a cryptographic info field.
///
/// Mirrors: MimeHeader[label L] in MimeHeader.jif
///
/// Six fields are public; `crypto_info` contains the session key
/// encrypted for the recipient.
#[derive(Clone)]
pub struct MimeHeader {
    // ---- Public fields ----
    pub to: String,
    pub from: String,
    pub date: String,
    pub subject: String,
    pub content_type: ContentType,
    pub mime_version: String,

    // ---- Crypto info ----
    /// The RSA-encrypted AES session key.
    ///
    /// In JPmail: stored as a Base64 string in the MIME header under
    /// `X-JPmail-CryptoInfo`.
    pub crypto_info: String,
}

impl MimeHeader {
    /// Create a MIME header for a new message.
    /// Mirrors: the constructor used in JPMailMessage.toMimeMailMessage()
    pub fn new(to: impl std::fmt::Display, from: impl std::fmt::Display, subject: impl std::fmt::Display, crypto_info: String) -> Self {
        MimeHeader {
            to: to.to_string(),
            from: from.to_string(),
            date: "[RFC-2822 date stub]".to_string(),
            subject: subject.to_string(),
            content_type: ContentType::multipart_mixed(&Self::generate_boundary()),
            mime_version: "1.0".to_string(),
            crypto_info,
        }
    }

    /// Serialize the public header fields to an RFC-2822 string.
    pub fn to_public_header_string(&self) -> String {
        format!(
            "From: {}\r\nTo: {}\r\nDate: {}\r\nSubject: {}\r\n\
             MIME-Version: {}\r\nContent-Type: {}\r\n",
            self.from,
            self.to,
            self.date,
            self.subject,
            self.mime_version,
            self.content_type.to_header(),
        )
    }

    /// Generate a MIME multipart boundary string.
    /// Mirrors: generateBoundary() in MimeHeader.jif
    pub fn generate_boundary() -> String {
        // In JPmail: uses System.currentTimeMillis() for uniqueness
        "----JPmail_Boundary_Stub_001".to_string()
    }
}
