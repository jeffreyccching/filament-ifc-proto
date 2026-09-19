// ============================================================================
// Mirrors: jpmail/src/pop3/MimePartBody.jif
//          jpmail/src/pop3/MimePart.jif
//          jpmail/src/pop3/MimePartBase64.jif
//          jpmail/src/pop3/MimePart7bit.jif
//          jpmail/src/pop3/MimePartHeader.jif
//
// A MIME message consists of a header section and one or more "parts".
// Each part has a header (public metadata) and a body.
// ============================================================================

use crate::pop3::content::{ContentDisposition, ContentType};

// ============================================================================
// MIME PART HEADER -- all fields are public metadata
// Mirrors: MimePartHeader.jif
// ============================================================================

/// Public header for a single MIME part.
///
/// All fields are public. The transfer encoding and content type tell
/// the mail client how to decode the part body.
#[derive(Clone)]
pub struct MimePartHeader {
    pub transfer_encoding: String,
    pub content_type: ContentType,
    pub content_disposition: Option<ContentDisposition>,
    pub other_metadata: String,
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
// MIME PART BODY -- abstract base
// Mirrors: MimePartBody.jif
// ============================================================================

/// Abstract base for MIME part bodies.
/// Mirrors: MimePartBody[label L] in MimePartBody.jif
pub trait MimePartBodyTrait {
    fn is_last(&self) -> bool;
    fn get_bytes(&self) -> &Vec<u8>;
}

// ============================================================================
// 7-BIT MIME PART BODY
// Mirrors: MimePart7bit.jif
// ============================================================================

/// A plain-text MIME part body with 7-bit encoding.
/// Mirrors: MimePart7bit[label L] extends MimePartBody[L]
#[derive(Clone)]
pub struct MimePart7bit {
    /// 7-bit encoded text body.
    pub body: String,
    /// boolean{} isLast -- public structural metadata.
    pub is_last: bool,
}

impl MimePart7bit {
    pub fn new(text: String) -> Self {
        MimePart7bit { body: text, is_last: false }
    }

    /// Build the raw bytes of this part (for MIME assembly).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.body.as_bytes().to_vec()
    }
}

// ============================================================================
// BASE64 MIME PART BODY
// Mirrors: MimePartBase64.jif
// ============================================================================

/// A Base64-encoded MIME part body (used for binary attachments and
/// encrypted payloads).
/// Mirrors: MimePartBase64[label L] extends MimePartBody[L]
#[derive(Clone)]
pub struct MimePartBase64 {
    /// Base64-encoded bytes.
    pub encoded_body: Vec<u8>,
    /// boolean{} isLast -- public structural metadata.
    pub is_last: bool,
}

impl MimePartBase64 {
    pub fn new(data: Vec<u8>) -> Self {
        // Stub: real impl calls Sun BASE64Encoder().encode(data)
        MimePartBase64 { encoded_body: data, is_last: false }
    }

    /// Decode the Base64 body back to raw bytes.
    pub fn decode(&self) -> Vec<u8> {
        // Stub: real impl calls Sun BASE64Decoder().decodeBuffer(...)
        self.encoded_body.clone()
    }
}

// ============================================================================
// MIME PART (combined header + body)
// Mirrors: MimePart.jif
// ============================================================================

/// A complete MIME part: a public header plus a body.
/// Mirrors: MimePart[label L] in MimePart.jif
///
/// The header is always public (Content-Type, transfer encoding).
#[derive(Clone)]
pub struct MimePart {
    /// Public metadata (content-type, transfer-encoding, disposition).
    pub header: MimePartHeader,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl MimePart {
    /// Build a 7-bit text part.
    /// Mirrors: static make7bitPart(String{L} bodyText, ...) in MimePart.jif
    pub fn make_7bit(text: String) -> Self {
        let bytes = text.as_bytes().to_vec();
        MimePart {
            header: MimePartHeader::new_7bit(),
            body: bytes,
        }
    }

    /// Build a Base64-encoded attachment part.
    /// Mirrors: static makeBase64Attachment(byte{L}[] data, String name, ...) in MimePart.jif
    pub fn make_base64(data: Vec<u8>, filename: &str) -> Self {
        MimePart {
            header: MimePartHeader::new_base64(filename),
            body: data,
        }
    }

    /// Serialize this part to a byte vector (for MIME assembly).
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_str = self.header.to_header_string();
        let mut all = header_str.into_bytes();
        all.extend_from_slice(b"\r\n");
        all.extend_from_slice(&self.body);
        all
    }
}
