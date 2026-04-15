
use crate::pop3::content::ContentType;

#[derive(Clone)]
pub struct MimeHeader {
    
    pub to: String,
    pub from: String,
    pub date: String,
    pub subject: String,
    pub content_type: ContentType,
    pub mime_version: String,

    pub crypto_info: String,
}

impl MimeHeader {
    
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

    pub fn generate_boundary() -> String {
        
        "----JPmail_Boundary_Stub_001".to_string()
    }
}
