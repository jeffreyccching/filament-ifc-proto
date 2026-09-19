// ============================================================================
// Mirrors: jpmail/src/pop3/ContentType.jif
//          jpmail/src/pop3/ContentDisposition.jif
//
// These classes parse MIME header parameters. Content-Type and
// Content-Disposition are *public* metadata -- the mail system (and indeed
// any SMTP relay) can see these values.
//
// ContentType.jif (abridged):
//   class ContentType {
//       protected String{} contentType;    // e.g. "text"
//       protected String{} subtype;        // e.g. "plain"
//       protected String{} boundary;       // multipart boundary
//       protected String{} name;
//       protected String{} charset;
//       protected String{} format;
//       static ContentType getContentType(BufferedReader br)
//   }
//
// ContentDisposition.jif (abridged):
//   class ContentDisposition {
//       protected String{} disposition;    // "inline" or "attachment"
//       protected String{} filename;
//       static ContentDisposition getContentDisposition(BufferedReader br)
//       boolean isAttachment()
//   }
// ============================================================================

/// MIME Content-Type parsed from an email header.
///
/// Mirrors: ContentType.jif
/// All fields are public (String{} in Jif -- raw, no label needed).
#[derive(Debug, Clone)]
pub struct ContentType {
    pub content_type: String,       // String{} e.g. "text", "multipart"
    pub subtype: String,            // String{} e.g. "plain", "mixed"
    pub boundary: Option<String>,   // String{} present in multipart/*
    pub name: Option<String>,       // String{} attachment filename hint
    pub charset: Option<String>,    // String{} e.g. "utf-8"
    pub format: Option<String>,     // String{} e.g. "flowed"
}

impl ContentType {
    pub fn text_plain() -> Self {
        ContentType {
            content_type: "text".to_string(),
            subtype: "plain".to_string(),
            boundary: None,
            name: None,
            charset: Some("utf-8".to_string()),
            format: None,
        }
    }

    pub fn multipart_mixed(boundary: &str) -> Self {
        ContentType {
            content_type: "multipart".to_string(),
            subtype: "mixed".to_string(),
            boundary: Some(boundary.to_string()),
            name: None,
            charset: None,
            format: None,
        }
    }

    /// Parse a Content-Type header value.
    /// Mirrors: static getContentType(BufferedReader br) in ContentType.jif
    pub fn parse(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.splitn(2, '/').collect();
        if parts.len() < 2 {
            return None;
        }
        let ctype = parts[0].trim().to_string();
        let rest = parts[1];
        let params: Vec<&str> = rest.splitn(2, ';').collect();
        let subtype = params[0].trim().to_string();

        let mut ct = ContentType {
            content_type: ctype,
            subtype,
            boundary: None,
            name: None,
            charset: None,
            format: None,
        };

        if let Some(params_str) = params.get(1) {
            for param in params_str.split(';') {
                let kv: Vec<&str> = param.splitn(2, '=').collect();
                if kv.len() == 2 {
                    let val = kv[1].trim().trim_matches('"').to_string();
                    match kv[0].trim() {
                        "boundary" => ct.boundary = Some(val),
                        "name"     => ct.name     = Some(val),
                        "charset"  => ct.charset  = Some(val),
                        "format"   => ct.format   = Some(val),
                        _ => {}
                    }
                }
            }
        }
        Some(ct)
    }

    /// True if this is a multipart/* content type.
    pub fn is_multipart(&self) -> bool {
        self.content_type.to_lowercase() == "multipart"
    }

    /// Format as a header value string.
    pub fn to_header(&self) -> String {
        let mut s = format!("{}/{}", self.content_type, self.subtype);
        if let Some(b) = self.boundary.as_ref() {
            s.push_str(&format!("; boundary=\"{}\"", b));
        }
        if let Some(c) = self.charset.as_ref() {
            s.push_str(&format!("; charset={}", c));
        }
        s
    }
}

// ============================================================================

/// MIME Content-Disposition parsed from an email header.
///
/// Mirrors: ContentDisposition.jif
/// All fields are public (String{} in Jif -- raw, no label needed).
#[derive(Debug, Clone)]
pub struct ContentDisposition {
    pub disposition: String,        // String{} "inline" or "attachment"
    pub filename: Option<String>,   // String{} attachment filename
}

impl ContentDisposition {
    pub fn inline() -> Self {
        ContentDisposition {
            disposition: "inline".to_string(),
            filename: None,
        }
    }

    pub fn attachment(filename: &str) -> Self {
        ContentDisposition {
            disposition: "attachment".to_string(),
            filename: Some(filename.to_string()),
        }
    }

    /// Parse a Content-Disposition header value.
    /// Mirrors: static getContentDisposition(BufferedReader br) in ContentDisposition.jif
    pub fn parse(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.splitn(2, ';').collect();
        if parts.is_empty() {
            return None;
        }
        let disposition = parts[0].trim().to_string();
        let mut cd = ContentDisposition { disposition, filename: None };

        if let Some(rest) = parts.get(1) {
            for param in rest.split(';') {
                let kv: Vec<&str> = param.splitn(2, '=').collect();
                if kv.len() == 2 && kv[0].trim() == "filename" {
                    cd.filename = Some(kv[1].trim().trim_matches('"').to_string());
                }
            }
        }
        Some(cd)
    }

    /// True if this is an attachment (not inline).
    /// Mirrors: isAttachment() in ContentDisposition.jif
    pub fn is_attachment(&self) -> bool {
        self.disposition.to_lowercase() == "attachment"
    }
}
