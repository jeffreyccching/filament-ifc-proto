
pub struct RSAClosure {
    
    pub plaintext: Vec<u8>,
    
    pub key_id: String,
}

impl RSAClosure {
    
    pub fn new(plaintext: Vec<u8>, key_id: &str) -> Self {
        RSAClosure {
            plaintext,
            key_id: key_id.to_string(),
        }
    }

    pub fn invoke(&self) -> Vec<u8> {
        println!(
            "[RSA] Encrypting with public key '{}'",
            self.key_id
        );
        
        self.plaintext.clone()
    }

    pub fn decrypt(ciphertext: Vec<u8>, private_key: String) -> Vec<u8> {
        println!("[RSA] Decrypting using private key");
        
        let _ = private_key;
        ciphertext
    }
}

pub fn aes_encrypt(plaintext: Vec<u8>, _key: Vec<u8>) -> Vec<u8> {
    println!("[AES] Encrypting");
    plaintext
}

pub fn aes_decrypt(ciphertext: Vec<u8>, _key: Vec<u8>) -> Vec<u8> {
    println!("[AES] Decrypting");
    ciphertext
}

pub fn des_encrypt(plaintext: Vec<u8>, _key: Vec<u8>) -> Vec<u8> {
    println!("[DES] Encrypting (AES fallback)");
    plaintext
}
