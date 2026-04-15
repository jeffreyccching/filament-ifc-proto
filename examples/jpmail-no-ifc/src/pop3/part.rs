
use crate::pop3::content::{ContentDisposition, ContentType};

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

    pub fn to_header_string(&self) -> String {
        let mut s = format!("Content-Type: {}\r\nContent-Transfer-Encoding: {}\r\n", self.content_type.to_header(), self.transfer_encoding);
        if let Some(disp) = self.content_disposition.as_ref() {
            s.push_str(&format!("Content-Disposition: {}\r\n", disp.disposition));
        }
        s
    }
}

pub trait MimePartBodyTrait {
    fn is_last(&self) -> bool;
    fn get_bytes(&self) -> &Vec<u8>;
}

#[derive(Clone)]
pub struct MimePart7bit {
    
    pub body: String,
    
    pub is_last: bool,
}

impl MimePart7bit {
    pub fn new(text: String) -> Self {
        MimePart7bit { body: text, is_last: false }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.body.as_bytes().to_vec()
    }
}

#[derive(Clone)]
pub struct MimePartBase64 {
    
    pub encoded_body: Vec<u8>,
    
    pub is_last: bool,
}

impl MimePartBase64 {
    pub fn new(data: Vec<u8>) -> Self {
        
        MimePartBase64 { encoded_body: data, is_last: false }
    }

    pub fn decode(&self) -> Vec<u8> {
        
        self.encoded_body.clone()
    }
}

#[derive(Clone)]
pub struct MimePart {
    
    pub header: MimePartHeader,
    
    pub body: Vec<u8>,
}

impl MimePart {
    
    pub fn make_7bit(text: String) -> Self {
        let bytes = text.as_bytes().to_vec();
        MimePart {
            header: MimePartHeader::new_7bit(),
            body: bytes,
        }
    }

    pub fn make_base64(data: Vec<u8>, filename: &str) -> Self {
        MimePart {
            header: MimePartHeader::new_base64(filename),
            body: data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let header_str = self.header.to_header_string();
        let mut all = header_str.into_bytes();
        all.extend_from_slice(b"\r\n");
        all.extend_from_slice(&self.body);
        all
    }
}
