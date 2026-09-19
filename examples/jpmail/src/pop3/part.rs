// ============================================================================
// Mirrors: jpmail/src/pop3/MimePartBody.jif
//          jpmail/src/pop3/MimePart.jif
//          jpmail/src/pop3/MimePartBase64.jif
//          jpmail/src/pop3/MimePart7bit.jif
//          jpmail/src/pop3/MimePartHeader.jif
//
// A MIME message consists of a header section and one or more "parts".
// Each part has a header (public metadata) and a body (labeled L).
//
// MimePartBody.jif (abstract base):
//   abstract class MimePartBody[label L] {
//       boolean{} isLast;   // true when this part ends with the boundary marker
//       boolean isLast()
//   }
//
// MimePart.jif:
//   class MimePart[label L] {
//       MimePartHeader{} header;    // public header metadata
//       MimePartBody[L]  body;      // labeled body
//       static MimePart make7bitPart(String{L} bodyText, ...)
//       static MimePart makeBase64Attachment(byte{L}[] data, ...)
//       static MimePart getMimePart(BufferedReader[L] br)
//   }
//
// MimePartBase64.jif:
//   class MimePartBase64[label L] extends MimePartBody[L] {
//       byte{L}[]  encodedBody;   // Base64-encoded bytes, labeled L
//   }
//
// MimePart7bit.jif:
//   class MimePart7bit[label L] extends MimePartBody[L] {
//       String{L} body;           // 7-bit text body, labeled L
//   }
//
// MimePartHeader.jif:
//   class MimePartHeader {
//       String{} transferEncoding;    // "7bit", "base64", "quoted-printable"
//       String{} contentType;
//       String{} contentDisposition;
//       String{} otherMetadata;
//   }
// ============================================================================

use crate::crypto::{authorized_declassify, DeclassAuthorization};
use crate::pop3::content::{ContentDisposition, ContentType};
use macros::mcall;
use typing_rules::lattice::*;

// ============================================================================
// MIME PART HEADER — all fields are public metadata
// Mirrors: MimePartHeader.jif
// ============================================================================

/// Public header for a single MIME part.
///
/// All fields are public (String{} in Jif — raw, no label needed).
/// The transfer encoding and content type tell the mail client how to
/// decode the part body, but are not themselves secret.
#[derive(Clone)]
pub struct MimePartHeader {
    pub transfer_encoding: String,                       // String{} transferEncoding
    pub content_type: ContentType,                       // String{} contentType
    pub content_disposition: Option<ContentDisposition>, // String{} contentDisposition
    pub other_metadata: String,                          // String{} otherMetadata
}

impl MimePartHeader {
    pub fn new_7bit() -> Self {
        MimePartHeader {
            transfer_encoding: "7bit".to_string(),
            content_type: ContentType::text_plain(),
            content_disposition: Some(ContentDisposition::inline()),
            other_metadata: String::new(),
        }
    }

    pub fn new_base64(filename: &str) -> Self {
        MimePartHeader {
            transfer_encoding: "base64".to_string(),
            content_type: ContentType {
                content_type: "application".to_string(),
                subtype: "octet-stream".to_string(),
                boundary: None,
                name: Some(filename.to_string()),
                charset: None,
                format: None,
            },
            content_disposition: Some(ContentDisposition::attachment(filename)),
            other_metadata: String::new(),
        }
    }

    /// Serialize to MIME header lines.
    pub fn to_header_string(&self) -> String {
        let mut s = format!("Content-Type: {}\r\nContent-Transfer-Encoding: {}\r\n", self.content_type.to_header(), self.transfer_encoding);
        if let Some(disp) = self.content_disposition.as_ref() {
            s.push_str(&format!("Content-Disposition: {}\r\n", disp.disposition));
        }
        s
    }
}

// ============================================================================
// MIME PART BODY — labeled abstract base
// Mirrors: MimePartBody.jif
// ============================================================================

/// Abstract base for MIME part bodies.
/// Mirrors: MimePartBody[label L] in MimePartBody.jif
///
/// `is_last` is public — it indicates whether this part ends the multipart
/// boundary, which is structural metadata, not content.
pub trait MimePartBodyTrait<L: Label> {
    fn is_last(&self) -> bool;
    fn get_bytes(&self) -> &Labeled<Vec<u8>, L>;
}

// ============================================================================
// 7-BIT MIME PART BODY
// Mirrors: MimePart7bit.jif
// ============================================================================

/// A plain-text MIME part body with 7-bit encoding.
/// Mirrors: MimePart7bit[label L] extends MimePartBody[L]
///
/// The body string is labeled L — the text content is as sensitive as
/// the overall message label.
#[derive(Clone)]
pub struct MimePart7bit<L: Label> {
    /// 7-bit encoded text body (labeled L).
    pub body: Labeled<String, L>, // String{L} body
    /// boolean{} isLast — public structural metadata.
    pub is_last: bool, // boolean{} isLast
}

impl<L: Label> MimePart7bit<L> {
    pub fn new(text: Labeled<String, L>) -> Self {
        MimePart7bit { body: text, is_last: false }
    }

    /// Build the raw bytes of this part (for MIME assembly).
    pub fn as_bytes(&self) -> Labeled<Vec<u8>, L> {
        // Bypass `mcall!` (it would emit `(&mut self.body)...` which fails
        // because `self` is `&self`). Use the `&self` form `__mcall` directly.
        (&self.body).__mcall(|inner| inner.as_bytes().to_vec())
    }
}

// ============================================================================
// BASE64 MIME PART BODY
// Mirrors: MimePartBase64.jif
// ============================================================================

/// A Base64-encoded MIME part body (used for binary attachments and
/// encrypted payloads).
/// Mirrors: MimePartBase64[label L] extends MimePartBody[L]
///
/// The encoded bytes are labeled L — even the Base64 form of ciphertext
/// is tracked because we know what it corresponds to.
#[derive(Clone)]
pub struct MimePartBase64<L: Label> {
    /// Base64-encoded bytes (labeled L).
    pub encoded_body: Labeled<Vec<u8>, L>, // byte{L}[] encodedBody
    /// boolean{} isLast — public structural metadata.
    pub is_last: bool, // boolean{} isLast
}

impl<L: Label> MimePartBase64<L> {
    pub fn new(data: Labeled<Vec<u8>, L>) -> Self {
        // Stub: real impl calls Sun BASE64Encoder().encode(data.value)
        MimePartBase64 { encoded_body: data, is_last: false }
    }

    /// Decode the Base64 body back to raw bytes.
    pub fn decode(&self) -> Labeled<Vec<u8>, L> {
        // Stub: real impl calls Sun BASE64Decoder().decodeBuffer(...)
        self.encoded_body.clone()
    }
}

// ============================================================================
// MIME PART (combined header + body)
// Mirrors: MimePart.jif
// ============================================================================

/// A complete MIME part: a public header plus a labeled body.
/// Mirrors: MimePart[label L] in MimePart.jif
///
/// The header is always public (Content-Type, transfer encoding).
/// The body bytes carry label L.
#[derive(Clone)]
pub struct MimePart<L: Label> {
    /// Public metadata (MimePartHeader{} in Jif — content-type, transfer-encoding, disposition).
    pub header: MimePartHeader, // MimePartHeader{} header
    /// The labeled body bytes.
    pub body: Labeled<Vec<u8>, L>, // MimePartBody[L] body
}

impl<L: Label> MimePart<L> {
    /// Build a 7-bit text part.
    /// Mirrors: static make7bitPart(String{L} bodyText, ...) in MimePart.jif
    pub fn make_7bit(mut text: Labeled<String, L>) -> Self {
        let bytes = mcall!(text.as_bytes().to_vec());
        MimePart {
            header: MimePartHeader::new_7bit(),
            body: bytes,
        }
    }

    /// Build a Base64-encoded attachment part.
    /// Mirrors: static makeBase64Attachment(byte{L}[] data, String name, ...) in MimePart.jif
    pub fn make_base64(data: Labeled<Vec<u8>, L>, filename: &str) -> Self {
        MimePart {
            header: MimePartHeader::new_base64(filename),
            body: data,
        }
    }

    /// Serialize this part to a byte vector (for MIME assembly).
    pub fn to_bytes(&self, auth: &DeclassAuthorization) -> Labeled<Vec<u8>, L> {
        let header_str = self.header.to_header_string();
        // Build complete part bytes within the body's label context
        let mut all = header_str.into_bytes();
        all.extend_from_slice(b"\r\n");
        all.extend_from_slice(&authorized_declassify(self.body.clone(), auth));
        Labeled::new(all)
    }
}
