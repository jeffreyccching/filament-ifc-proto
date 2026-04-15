
pub mod content;
pub mod header;
pub mod message;
pub mod part;

use crate::crypto::{authorized_declassify, DeclassAuthorization};
use crate::net::SecureSocket;
use crate::password::Password;
use crate::policy::KeyPrincipal;
use crate::pop3::message::{JPMailMessage, MimeMailMessage};
use crate::smtp::auth::DigestApop;
use macros::mcall;
use typing_rules::lattice::*;

pub struct MailReaderCrypto<L: Label> {
    
    pub server: String, 
    
    pub principal_name: String,
    
    pub username: Labeled<String, L>, 
    
    pub password: Labeled<String, L>, 
    
    pub key_principal: KeyPrincipal<L>,
    
    pub messages: Vec<JPMailMessage<L>>,
    
    encrypted_spool: Vec<MimeMailMessage<L>>,
}

impl<L: Label> MailReaderCrypto<L> {
    
    pub fn new(server: &str, principal_name: &str, username: Labeled<String, L>, password: Labeled<String, L>) -> Self {
        let key_principal = KeyPrincipal::new(principal_name, &format!("demo/certs-{}/", principal_name), password.clone());
        MailReaderCrypto {
            server: server.to_string(),
            principal_name: principal_name.to_string(),
            username,
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    pub fn from_password_file(server: &str, username: &str, cert_dir: &str) -> Self {
        let username_labeled = Labeled::<String, L>::new(username.to_string());
        let pw_file = Password::<L>::new(&format!("demo/passwd-{}/", username));
        let password = pw_file.get_password();
        let key_principal = KeyPrincipal::new(username, cert_dir, password.clone());
        MailReaderCrypto {
            server: server.to_string(),
            principal_name: username.to_string(),
            username: username_labeled,
            password,
            key_principal,
            messages: Vec::new(),
            encrypted_spool: Vec::new(),
        }
    }

    pub fn connect(&self) -> SecureSocket<L> {
        println!("[POP3] Connecting to {}:110", self.server);
        let auth = DeclassAuthorization::new(&self.principal_name);
        let socket = authorized_declassify(SecureSocket::<L>::create(&self.server, 110), &auth);
        
        let greeting = authorized_declassify(socket.read_line(), &auth);
        println!("[POP3] Server: {}", greeting);
        socket
    }

    pub fn authenticate(&self, socket: &SecureSocket<L>) -> Labeled<bool, L> {
        println!("[POP3] Authenticating (APOP)");
        
        let apop_auth = DeclassAuthorization::new(&self.principal_name);
        let apop = DigestApop::new(self.password.clone());
        let challenge = socket.read_line(); 
        let digest = apop.compute_apop_digest(challenge, &apop_auth);

        let auth = DeclassAuthorization::new(&self.principal_name);
        let user_cmd = Labeled::<String, L>::new(format!("USER {}", authorized_declassify(self.username.clone(), &auth)));
        socket.write_line(user_cmd);
        
        let _ = digest;

        let response = socket.read_line();
        mcall!(response.starts_with("+OK"))
    }

    pub fn fetch_encrypted_messages(&mut self, socket: &SecureSocket<L>) {
        println!("[POP3] Fetching message list (LIST)...");
        socket.send_command("LIST");
        let list_response = socket.read_line();
        println!("[POP3] [labeled list response]");

        println!("[POP3] RETR 1");
        let raw = socket.read_line(); 
        let _ = raw;

        let crypto_info: Labeled<String, L> = Labeled::new("[rsa_wrapped_aes_key_stub]".to_string());
        let auth = DeclassAuthorization::new(&self.principal_name);
        let header = crate::pop3::header::MimeHeader::new(&authorized_declassify(self.username.clone(), &auth), "sender@example.com", "(encrypted subject stub)", crypto_info);
        let encrypted_body_bytes: Labeled<Vec<u8>, L> = Labeled::new(b"[encrypted_body_stub]".to_vec());
        let part = crate::pop3::part::MimePart::make_base64(encrypted_body_bytes, "body.enc");
        let mime_msg = MimeMailMessage { header, parts: vec![part] };
        self.encrypted_spool.push(mime_msg);
    }

    pub fn decrypt_messages(&mut self) {
        println!("[POP3] Decrypting {} messages...", self.encrypted_spool.len());
        let auth = DeclassAuthorization::new(&self.principal_name);
        let private_key = self.key_principal.get_private_key();
        for mime in self.encrypted_spool.drain(..) {
            let plain = mime.decrypt(private_key.clone(), &auth);
            self.messages.push(plain);
        }
    }

    pub fn retrieve_messages(&mut self) {
        let socket = self.connect();
        let auth_ok = self.authenticate(&socket);
        if auth_ok == false {
            println!("[POP3] Authentication FAILED — aborting.");
            return;
        }
        self.fetch_encrypted_messages(&socket);
        self.decrypt_messages();
        socket.send_command("QUIT");
        println!("[POP3] Session closed.");
    }

    pub fn display_headers(msg: &JPMailMessage<L>) {
        println!("  From   : {}", msg.from); 
        println!("  To     : [Labeled<String, L>]"); 
        println!("  Subject: {}", msg.subject); 
    }

    pub fn display_message(&self, msg: &JPMailMessage<L>) {
        println!("  --- Message ---");
        Self::display_headers(msg);
        println!("  Body   : [Labeled<String, L> — requires authorized declassification]");
    }

    pub fn display_body_publicly(msg: &JPMailMessage<L>)
    where
        L: LEQ<Public>,
    {
        println!("  Body (public): {}", declassify(msg.body.clone()));
    }

    pub fn message_count(&self) -> Labeled<usize, L> {
        let msgs: Labeled<&Vec<JPMailMessage<L>>, L> = Labeled::new(&self.messages);
        mcall!(msgs.len())
    }
}
