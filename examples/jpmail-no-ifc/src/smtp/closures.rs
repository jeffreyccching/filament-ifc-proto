
use crate::pop3::message::JPMailMessage;

pub struct DeclassMsgBodyClosure {
    
    pub msg_body: String,
    
    pub recipient_key_id: String,
}

impl DeclassMsgBodyClosure {
    pub fn new(msg_body: String, recipient_key_id: &str) -> Self {
        DeclassMsgBodyClosure {
            msg_body,
            recipient_key_id: recipient_key_id.to_string(),
        }
    }

    pub fn invoke(&self) -> Vec<u8> {
        println!(
            "[DeclassMsgBodyClosure] Encrypting body for recipient '{}'",
            self.recipient_key_id,
        );
        
        self.msg_body.as_bytes().to_vec()
    }
}

pub struct DeclassStringClosure {
    
    pub labeled_string: String,
}

impl DeclassStringClosure {
    pub fn new(labeled_string: String) -> Self {
        DeclassStringClosure { labeled_string }
    }

    pub fn invoke(&self) -> String {
        println!(
            "[DeclassStringClosure] Declassifying string",
        );
        self.labeled_string.clone()
    }
}

pub struct EmailHdrDeclassClosure {
    
    pub message: JPMailMessage,
}

impl EmailHdrDeclassClosure {
    pub fn new(message: JPMailMessage) -> Self {
        EmailHdrDeclassClosure { message }
    }

    pub fn invoke(&self) -> String {
        println!(
            "[EmailHdrDeclassClosure] Declassifying headers for '{}'",
            self.message.subject,
        );
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nX-JPmail-CryptoInfo: [declassified_key_stub]",
            self.message.from, self.message.to, self.message.subject
        )
    }
}

pub struct EmailDisclaimerClosure {
    
    pub body: String,
}

const DISCLAIMER: &str = "\r\n\r\n\
    -----------------------------------------------------------------------\r\n\
    This message and any attachments may contain confidential information.\r\n\
    If you are not the intended recipient, please notify the sender and\r\n\
    delete this message. Any unauthorized use, disclosure, or distribution\r\n\
    of this message is strictly prohibited.\r\n\
    -----------------------------------------------------------------------";

impl EmailDisclaimerClosure {
    pub fn new(body: String) -> Self {
        EmailDisclaimerClosure { body }
    }

    pub fn invoke(&self) -> String {
        let mut body = self.body.clone();
        body.push_str(DISCLAIMER);
        println!(
            "[EmailDisclaimerClosure] Appended disclaimer, declassifying",
        );
        body
    }
}
