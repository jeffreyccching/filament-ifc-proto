
pub mod content;
pub mod header;
pub mod message;
pub mod part;

use crate::net::SecureSocket;
use crate::password::Password;
use crate::policy::KeyPrincipal;
use crate::pop3::message::{JPMailMessage, MimeMailMessage};
use crate::smtp::auth::DigestApop;

pub struct MailReaderCrypto {
    
    pub server: String,
    
    pub username: String,
    
    pub password: String,
    
    pub key_principal: KeyPrincipal,
    
    pub messages: Vec<JPMailMessage>,
    
    encrypted_spool: Vec<MimeMailMessage>,
}

impl MailReaderCrypto {
    
    pub fn new(server: &str, username: &str, password: String) -> Self {
        let key_principal = KeyPrincipal::new(
            username,
            &format!("demo/certs-{}/", username),
            password.clone(),
        );
        MailReaderCrypto {
            server: server.to_string(),
            username: username.to_string(),
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    pub fn from_password_file(server: &str, username: &str, cert_dir: &str) -> Self {
        let pw_file = Password::new(&format!("demo/passwd-{}/", username));
        let password = pw_file.get_password();
        let key_principal = KeyPrincipal::new(username, cert_dir, password.clone());
        MailReaderCrypto {
            server: server.to_string(),
            username: username.to_string(),
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    pub fn connect(&self) -> SecureSocket {
        println!("[POP3] Connecting to {}:110", self.server);
        let socket = SecureSocket::create(&self.server, 110);
        
        let greeting = socket.read_line();
        println!("[POP3] Server: {}", greeting);
        socket
    }

    pub fn authenticate(&self, socket: &SecureSocket) -> bool {
        println!("[POP3] Authenticating (APOP)");
        
        let apop = DigestApop::new(self.password.clone());
        let challenge = socket.read_line(); 
        let digest = apop.compute_apop_digest(challenge);

        let user_cmd = format!("USER {}", self.username);
        socket.write_line(user_cmd);
        let _ = digest;

        let response = socket.read_line();
        response.starts_with("+OK")
    }

    pub fn fetch_encrypted_messages(&mut self, socket: &SecureSocket) {
        println!("[POP3] Fetching message list (LIST)...");
        socket.send_command("LIST");
        let _list_response = socket.read_line();
        println!("[POP3] [list response]");

        println!("[POP3] RETR 1");
        let raw = socket.read_line();
        let _ = raw;

        let crypto_info: String = "[rsa_wrapped_aes_key_stub]".to_string();
        let header = crate::pop3::header::MimeHeader::new(
            &self.username,
            "sender@example.com",
            "(encrypted subject stub)",
            crypto_info,
        );
        let encrypted_body_bytes: Vec<u8> = b"[encrypted_body_stub]".to_vec();
        let part = crate::pop3::part::MimePart::make_base64(encrypted_body_bytes, "body.enc");
        let mime_msg = MimeMailMessage { header, parts: vec![part] };
        self.encrypted_spool.push(mime_msg);
    }

    pub fn decrypt_messages(&mut self) {
        println!("[POP3] Decrypting {} messages...", self.encrypted_spool.len());
        let private_key = self.key_principal.get_private_key();
        for mime in self.encrypted_spool.drain(..) {
            let plain = mime.decrypt(private_key.clone());
            self.messages.push(plain);
        }
    }

    pub fn retrieve_messages(&mut self) {
        let socket = self.connect();
        let auth_ok = self.authenticate(&socket);
        if !auth_ok {
            println!("[POP3] Authentication FAILED -- aborting.");
            return;
        }
        self.fetch_encrypted_messages(&socket);
        self.decrypt_messages();
        socket.send_command("QUIT");
        println!("[POP3] Session closed.");
    }

    pub fn display_headers(msg: &JPMailMessage) {
        println!("  From   : {}", msg.from);
        println!("  To     : {}", msg.to);
        println!("  Subject: {}", msg.subject);
    }

    pub fn display_message(&self, msg: &JPMailMessage) {
        println!("  --- Message ---");
        Self::display_headers(msg);
        println!("  Body   : [requires authorized access]");
    }

    pub fn display_body_publicly(msg: &JPMailMessage) {
        println!("  Body (public): {}", msg.body);
    }

    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}
