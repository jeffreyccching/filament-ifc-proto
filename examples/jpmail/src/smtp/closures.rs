
use crate::crypto::{authorized_declassify, DeclassAuthorization};
use crate::pop3::message::JPMailMessage;
use macros::mcall;
use typing_rules::lattice::*;

pub struct DeclassMsgBodyClosure<L: Label> {
    
    pub msg_body: Labeled<String, L>,              
    
    pub recipient_key_id: String, 
}

impl<L: Label> DeclassMsgBodyClosure<L> {
    pub fn new(msg_body: Labeled<String, L>, recipient_key_id: &str) -> Self {
        DeclassMsgBodyClosure {
            msg_body,
            recipient_key_id: recipient_key_id.to_string(),
        }
    }

    pub fn invoke(&self, auth: DeclassAuthorization) -> Vec<u8> {
        println!(
            "[DeclassMsgBodyClosure] Encrypting body for recipient '{}' (auth: {})",
            self.recipient_key_id,
            auth.granted_by
        );
        
        authorized_declassify(mcall!(self.msg_body.as_bytes().to_vec()), &auth)
    }
}

pub struct DeclassStringClosure<L: Label> {
    
    pub labeled_string: Labeled<String, L>,
}

impl<L: Label> DeclassStringClosure<L> {
    pub fn new(labeled_string: Labeled<String, L>) -> Self {
        DeclassStringClosure { labeled_string }
    }

    pub fn invoke(&self, auth: DeclassAuthorization) -> String {
        println!(
            "[DeclassStringClosure] Declassifying string (auth: {})",
            auth.granted_by
        );
        
        authorized_declassify(self.labeled_string.clone(), &auth)
    }
}

pub struct EmailHdrDeclassClosure<L: Label> {
    
    pub message: JPMailMessage<L>,
}

impl<L: Label> EmailHdrDeclassClosure<L> {
    pub fn new(message: JPMailMessage<L>) -> Self {
        EmailHdrDeclassClosure { message }
    }

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

pub struct EmailDisclaimerClosure<L: Label> {
    
    pub body: Labeled<String, L>,
}

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

    pub fn invoke(&self, auth: DeclassAuthorization) -> String {
        
        let mut body = authorized_declassify(mcall!(self.body.clone()), &auth);
        body.push_str(DISCLAIMER);
        println!(
            "[EmailDisclaimerClosure] Appended disclaimer, declassifying (auth: {})",
            auth.granted_by
        );
        body
    }
}
