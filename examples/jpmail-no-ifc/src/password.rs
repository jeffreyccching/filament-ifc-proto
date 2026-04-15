
pub struct Password {
    
    pub encrypted_file: String,
    
    pub iv_file: String,
    
    pub key_file: String,
}

impl Password {
    
    pub fn new(base_path: &str) -> Self {
        Password {
            encrypted_file: format!("{}password", base_path),
            iv_file: format!("{}password_iv", base_path),
            key_file: format!("{}password_key", base_path),
        }
    }

    pub fn get_password(&self) -> String {
        println!(
            "[Password] Reading encrypted credential from '{}'",
            self.encrypted_file
        );
        
        format!("[decrypted_from:{}]", self.encrypted_file)
    }

    pub fn set_password(&self, pwd: String) {
        println!(
            "[Password] Storing encrypted credential to '{}'",
            self.encrypted_file
        );
        
        drop(pwd);
    }

    pub fn to_base64(data: &[u8]) -> String {
        
        format!("[base64:{}bytes]", data.len())
    }
}

pub struct NewPassword;

impl NewPassword {
    
    pub fn bootstrap(username: &str, plaintext: String) {
        println!(
            "[NewPassword] Bootstrapping encrypted credential for principal '{}'",
            username
        );
        println!(
            "[NewPassword] Verifying delegation: 'me actsFor {}' ...",
            username
        );
        
        let pw = Password::new(&format!("demo/passwd-{}/", username));
        pw.set_password(plaintext);
        println!("[NewPassword] Done -- password file written.");
    }
}
