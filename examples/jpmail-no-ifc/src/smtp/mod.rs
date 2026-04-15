
pub mod auth;
pub mod closures;

use crate::net::SecureSocket;
use crate::password::Password;
use crate::pop3::message::JPMailMessage;
use crate::smtp::auth::DigestMD5;
use crate::smtp::closures::{
    DeclassMsgBodyClosure, DeclassStringClosure, EmailDisclaimerClosure, EmailHdrDeclassClosure,
};

pub struct MailSenderCrypto {
    
    pub smtp_server: String,
    
    pub smtp_username: String,
    
    pub email_address: String,
    
    pub smtp_password: String,
}

impl MailSenderCrypto {
    
    pub fn new(
        smtp_server: &str,
        smtp_username: &str,
        email_address: &str,
        smtp_password: String,
    ) -> Self {
        MailSenderCrypto {
            smtp_server: smtp_server.to_string(),
            smtp_username: smtp_username.to_string(),
            email_address: email_address.to_string(),
            smtp_password,
        }
    }

    pub fn from_password_file(
        smtp_server: &str,
        smtp_username: &str,
        email_address: &str,
        password_dir: &str,
    ) -> Self {
        let pw_file = Password::new(&format!("demo/{}", password_dir));
        let smtp_password = pw_file.get_password();
        MailSenderCrypto {
            smtp_server: smtp_server.to_string(),
            smtp_username: smtp_username.to_string(),
            email_address: email_address.to_string(),
            smtp_password,
        }
    }

    fn connect_smtp(&self) -> SecureSocket {
        println!("[SMTP] Connecting to {}:587", self.smtp_server);
        let socket = SecureSocket::create(&self.smtp_server, 587);
        let greeting = socket.read_line();
        println!("[SMTP] Server: {}", greeting);
        socket
    }

    fn authenticate_smtp(&self, socket: &SecureSocket) {
        println!("[SMTP] Initiating DIGEST-MD5 authentication...");
        socket.send_command("AUTH DIGEST-MD5");

        let challenge_pub = socket.read_line();
        println!("[SMTP] Challenge: {}", challenge_pub);

        let auth = DigestMD5::new(
            self.smtp_password.clone(),
            &self.smtp_username,
            "cse.psu.edu",
        );

        let response: String = auth.auth_client(challenge_pub);

        let closure = DeclassStringClosure::new(response);
        let public_response: String = closure.invoke();

        socket.send_command(&public_response);

        let result = socket.read_line();
        println!("[SMTP] Auth result: {}", result);
    }

    pub fn send_message(&self, msg: &JPMailMessage, recipient_key_id: &str) {
        println!("\n[SMTP] Preparing to send message: '{}'", msg.subject);

        let _mime = msg.to_mime(recipient_key_id);

        let socket = self.connect_smtp();
        socket.send_command(&format!("EHLO {}", self.email_address));
        self.authenticate_smtp(&socket);

        let to_closure = DeclassStringClosure::new(msg.to.clone());
        let public_to: String = to_closure.invoke();
        socket.send_command(&format!("MAIL FROM:<{}>", self.email_address));
        socket.send_command(&format!("RCPT TO:<{}>", public_to));
        socket.send_command("DATA");

        let hdr_closure = EmailHdrDeclassClosure::new(msg.clone());
        let public_headers: String = hdr_closure.invoke();
        socket.send_command(&public_headers);

        let body_closure = DeclassMsgBodyClosure::new(msg.body.clone(), recipient_key_id);
        let encrypted_body: Vec<u8> = body_closure.invoke();
        println!(
            "[SMTP] Sending {} bytes encrypted body (declassified via RSA)",
            encrypted_body.len()
        );

        let disclaimer = EmailDisclaimerClosure::new(msg.body.clone());
        let body_with_note: String = disclaimer.invoke();
        
        let _ = body_with_note;

        socket.send_command(".");
        let response = socket.read_line();
        println!("[SMTP] Server accepted: {}", response);
        socket.send_command("QUIT");
        println!("[SMTP] Message '{}' sent successfully.", msg.subject);
    }
}
