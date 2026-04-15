
use crate::crypto::{aes_encrypt, authorized_declassify, des_encrypt, DeclassAuthorization, RSAClosure};
use crate::pop3::header::MimeHeader;
use crate::pop3::part::MimePart;
use macros::mcall;
use typing_rules::lattice::*;

#[derive(Clone)]
pub struct JPMailMessage<L: Label> {
    
    pub from: String, 
    
    pub to: Labeled<String, L>, 
    
    pub subject: String, 
    
    pub body: Labeled<String, L>, 
}

impl<L: Label> JPMailMessage<L> {
    
    pub fn new(from: &str, to: &str, subject: &str, body: Labeled<String, L>) -> Self {
        JPMailMessage {
            from: from.to_string(),
            to: Labeled::new(to.to_string()),
            subject: subject.to_string(),
            body,
        }
    }

    pub fn to_mime(&self, recipient_key_id: &str) -> MimeMailMessage<L> {
        println!("[JPMailMessage] Converting to MIME (encrypting body)...");

        let session_key: Labeled<Vec<u8>, L> = Labeled::new(b"stub_aes_session_key_32bytes!!!!".to_vec());

        let body_bytes: Labeled<Vec<u8>, L> = mcall!(self.body.as_bytes().to_vec());
        let encrypted_body = aes_encrypt(body_bytes, session_key.clone());
        
        let _ = des_encrypt(encrypted_body.clone(), session_key.clone()); 

        let rsa = RSAClosure::new(session_key, recipient_key_id);
        let wrapped_key: Labeled<Vec<u8>, L> = rsa.invoke();

        let auth = DeclassAuthorization::new(&self.from);
        let crypto_info: Labeled<String, L> = Labeled::new(format!("[base64_rsa_wrapped_key:{}]", authorized_declassify(mcall!(wrapped_key.len()), &auth)));

        let header = MimeHeader::new(&authorized_declassify(self.to.clone(), &auth), &self.from, &self.subject, crypto_info);

        let body_part = MimePart::make_base64(encrypted_body, "body.enc");

        MimeMailMessage { header, parts: vec![body_part] }
    }
}

#[derive(Clone)]
pub struct MimeMailMessage<L: Label> {
    
    pub header: MimeHeader<L>,
    
    pub parts: Vec<MimePart<L>>,
}

impl<L: Label> MimeMailMessage<L> {
    
    pub fn show_public_headers(&self) {
        println!("  From   : {}", self.header.from);
        println!("  To     : {}", self.header.to);
        println!("  Subject: {}", self.header.subject);
        println!("  MIME-Version: {}", self.header.mime_version);
    }

    pub fn decrypt(&self, private_key: Labeled<String, L>, auth: &DeclassAuthorization) -> JPMailMessage<L> {
        println!("[MimeMailMessage] Decrypting message...");

        let wrapped_key_bytes: Labeled<Vec<u8>, L> = Labeled::new(b"stub_wrapped_key".to_vec());
        let session_key = RSAClosure::decrypt(wrapped_key_bytes, private_key);

        let body_bytes = if let Some(part) = self.parts.first() {
            crate::crypto::aes_decrypt(part.body.clone(), session_key)
        } else {
            Labeled::new(Vec::new())
        };

        let body_text: Labeled<String, L> = Labeled::new(
            String::from_utf8(authorized_declassify(body_bytes, auth)).unwrap_or_else(|_| "[decode error]".into()),
        );

        JPMailMessage {
            from: self.header.from.clone(),
            to: Labeled::new(self.header.to.clone()),
            subject: self.header.subject.clone(),
            body: body_text,
        }
    }
}
