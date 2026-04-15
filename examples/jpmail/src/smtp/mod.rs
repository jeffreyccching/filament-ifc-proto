
pub mod auth;
pub mod closures;

use crate::crypto::DeclassAuthorization;
use crate::net::SecureSocket;
use crate::password::Password;
use crate::pop3::message::JPMailMessage;
use crate::smtp::auth::DigestMD5;
use crate::smtp::closures::{
    DeclassMsgBodyClosure, DeclassStringClosure, EmailDisclaimerClosure, EmailHdrDeclassClosure,
};
use typing_rules::lattice::*;

pub struct MailSenderCrypto<L: Label> {
    
    pub smtp_server: String,    
    
    pub smtp_username: String,  
    
    pub email_address: String,  
    
    pub smtp_password: Labeled<String, L>,       
}

impl<L: Label> MailSenderCrypto<L> {
    
    pub fn new(
        smtp_server: &str,
        smtp_username: &str,
        email_address: &str,
        smtp_password: Labeled<String, L>,
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
        let pw_file = Password::<L>::new(&format!("demo/{}", password_dir));
        let smtp_password = pw_file.get_password();
        MailSenderCrypto {
            smtp_server: smtp_server.to_string(),
            smtp_username: smtp_username.to_string(),
            email_address: email_address.to_string(),
            smtp_password,
        }
    }

    fn connect_smtp(&self) -> SecureSocket<Public> {
        println!("[SMTP] Connecting to {}:587", self.smtp_server);
        let socket = SecureSocket::<Public>::create(&self.smtp_server, 587);
        let socket = declassify(socket);
        let greeting = socket.read_line();
        println!("[SMTP] Server: {}", declassify(greeting));
        socket
    }

    fn authenticate_smtp(&self, socket: &SecureSocket<Public>) {
        println!("[SMTP] Initiating DIGEST-MD5 authentication...");
        socket.send_command("AUTH DIGEST-MD5");

        let challenge_pub = socket.read_line();
        println!("[SMTP] Challenge: {}", declassify(challenge_pub.clone()));

        let auth = DigestMD5::new(
            self.smtp_password.clone(),
            &self.smtp_username,
            "cse.psu.edu",
        );

        let challenge_l: Labeled<String, L> = Labeled::new(declassify(challenge_pub));
        let response_labeled: Labeled<String, L> = auth.auth_client(challenge_l);

        let auth_token = DeclassAuthorization::new(&self.smtp_username);
        let closure = DeclassStringClosure::new(response_labeled);
        let public_response: String = closure.invoke(auth_token);

        socket.send_command(&public_response);

        let result = socket.read_line();
        println!("[SMTP] Auth result: {}", declassify(result));
    }

    pub fn send_message(&self, msg: &JPMailMessage<L>, recipient_key_id: &str) {
        println!("\n[SMTP] Preparing to send message: '{}'", msg.subject);

        let mime = msg.to_mime(recipient_key_id);

        let socket = self.connect_smtp();
        socket.send_command(&format!("EHLO {}", self.email_address));
        self.authenticate_smtp(&socket);

        let rcpt_auth = DeclassAuthorization::new(&self.smtp_username);
        let to_closure = DeclassStringClosure::new(msg.to.clone());
        let public_to: String = to_closure.invoke(rcpt_auth);
        socket.send_command(&format!("MAIL FROM:<{}>", self.email_address));
        socket.send_command(&format!("RCPT TO:<{}>", public_to));
        socket.send_command("DATA");

        let hdr_auth = DeclassAuthorization::new(&self.smtp_username);
        let hdr_closure = EmailHdrDeclassClosure::new(msg.clone());
        let public_headers: String = hdr_closure.invoke(hdr_auth);
        socket.send_command(&public_headers);

        let body_auth = DeclassAuthorization::new(&self.smtp_username);
        let body_closure = DeclassMsgBodyClosure::new(msg.body.clone(), recipient_key_id);
        let encrypted_body: Vec<u8> = body_closure.invoke(body_auth);
        println!(
            "[SMTP] Sending {} bytes encrypted body (declassified via RSA)",
            encrypted_body.len()
        );

        let disc_auth = DeclassAuthorization::new(&self.smtp_username);
        let disclaimer = EmailDisclaimerClosure::new(msg.body.clone());
        let body_with_note: String = disclaimer.invoke(disc_auth);
        
        let _ = body_with_note;

        socket.send_command(".");
        let response = socket.read_line();
        println!("[SMTP] Server accepted: {}", declassify(response));
        socket.send_command("QUIT");
        println!("[SMTP] Message '{}' sent successfully.", msg.subject);
    }
}
