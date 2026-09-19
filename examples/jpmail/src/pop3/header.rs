// ============================================================================
// Mirrors: jpmail/src/pop3/MimeHeader.jif
//
// Jif source (abridged):
//   class MimeHeader[label L] {
//       protected String{} to;         // Public: recipient address
//       protected String{} from;       // Public: sender address
//       protected String{} date;       // Public: date string
//       protected String{} subject;    // Public: subject line
//       protected String{} contentType;// Public: MIME content type
//       protected String{} mimeVersion;// Public: MIME version
//       protected String{L} cryptoInfo;// LABELED: encrypted key info
//
//       static MimeHeader getMimeHeader(BufferedReader[L] br, label L)
//       String generateBoundary()
//   }
//
// Note: six of the seven fields are public; only cryptoInfo is labeled L.
// cryptoInfo carries the RSA-encrypted AES session key — it is labeled
// because we know it corresponds to label-L content.
// ============================================================================

use crate::pop3::content::ContentType;
use typing_rules::lattice::*;

/// MIME message header with a labeled cryptographic info field.
///
/// Mirrors: MimeHeader[label L] in MimeHeader.jif
///
/// Six fields are public (labeled `{}` in Jif — raw here);
/// only `crypto_info` is labeled L because it contains the session key
/// encrypted for the L-level principal.
#[derive(Clone)]
pub struct MimeHeader<L: Label> {
    // ---- Public fields (String{} in Jif — raw) ----
    pub to: String,                // String{} to
    pub from: String,              // String{} from
    pub date: String,              // String{} date
    pub subject: String,           // String{} subject
    pub content_type: ContentType, // String{} contentType
    pub mime_version: String,      // String{} mimeVersion

    // ---- Labeled field ----
    /// The RSA-encrypted AES session key (labeled L).
    ///
    /// In JPmail: stored as a Base64 string in the MIME header under
    /// `X-JPmail-CryptoInfo`. It is labeled L because decrypting it
    /// reveals the AES key used to encrypt the L-level message body.
    pub crypto_info: Labeled<String, L>, // String{L} cryptoInfo
}

impl<L: Label> MimeHeader<L> {
    /// Create a MIME header for a new message.
    /// Mirrors: the constructor used in JPMailMessage.toMimeMailMessage()
    pub fn new(to: impl std::fmt::Display, from: impl std::fmt::Display, subject: impl std::fmt::Display, crypto_info: Labeled<String, L>) -> Self {
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
    /// (crypto_info is intentionally omitted — it appears as a separate
    ///  X-JPmail-CryptoInfo header only when the sender has clearance L.)
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
