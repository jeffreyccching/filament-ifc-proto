
use crate::crypto::{aes_encrypt, des_encrypt, RSAClosure};
use crate::pop3::header::MimeHeader;
use crate::pop3::part::MimePart;

#[derive(Clone)]
pub struct JPMailMessage {
    
    pub from: String,
    
    pub to: String,
    
    pub subject: String,
    
    pub body: String,
}

impl JPMailMessage {
    
    pub fn new(from: &str, to: &str, subject: &str, body: String) -> Self {
        JPMailMessage {
            from: from.to_string(),
            to: to.to_string(),
            subject: subject.to_string(),
            body,
        }
    }

    pub fn to_mime(&self, recipient_key_id: &str) -> MimeMailMessage {
        println!("[JPMailMessage] Converting to MIME (encrypting body)...");

        let session_key: Vec<u8> = b"stub_aes_session_key_32bytes!!!!".to_vec();

        let body_bytes: Vec<u8> = self.body.as_bytes().to_vec();
        let encrypted_body = aes_encrypt(body_bytes, session_key.clone());
        
        let _ = des_encrypt(encrypted_body.clone(), session_key.clone()); 

        let rsa = RSAClosure::new(session_key, recipient_key_id);
        let wrapped_key: Vec<u8> = rsa.invoke();

        let crypto_info: String = format!("[base64_rsa_wrapped_key:{}]", wrapped_key.len());

        let header = MimeHeader::new(&self.to, &self.from, &self.subject, crypto_info);

        let body_part = MimePart::make_base64(encrypted_body, "body.enc");

        MimeMailMessage { header, parts: vec![body_part] }
    }
}

#[derive(Clone)]
pub struct MimeMailMessage {
    
    pub header: MimeHeader,
    
    pub parts: Vec<MimePart>,
}

impl MimeMailMessage {
    
    pub fn show_public_headers(&self) {
        println!("  From   : {}", self.header.from);
        println!("  To     : {}", self.header.to);
        println!("  Subject: {}", self.header.subject);
        println!("  MIME-Version: {}", self.header.mime_version);
    }

    pub fn decrypt(&self, private_key: String) -> JPMailMessage {
        println!("[MimeMailMessage] Decrypting message...");

        let wrapped_key_bytes: Vec<u8> = b"stub_wrapped_key".to_vec();
        let session_key = RSAClosure::decrypt(wrapped_key_bytes, private_key);

        let body_bytes = if let Some(part) = self.parts.first() {
            crate::crypto::aes_decrypt(part.body.clone(), session_key)
        } else {
            Vec::new()
        };

        let body_text: String =
            String::from_utf8(body_bytes).unwrap_or_else(|_| "[decode error]".into());

        JPMailMessage {
            from: self.header.from.clone(),
            to: self.header.to.clone(),
            subject: self.header.subject.clone(),
            body: body_text,
        }
    }
}
