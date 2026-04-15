
#[derive(Debug)]
pub struct SecureSocket {
    
    pub host: String,
    
    pub port: u16,
    
    pub use_ssl: bool,
}

impl SecureSocket {
    
    pub fn create(host: impl std::fmt::Display, port: u16) -> Self {
        println!("[Socket] Connecting {}:{} (plain TCP)", host, port);
        SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: false,
        }
    }

    pub fn create_ssl(host: &str, port: u16) -> Self {
        println!("[Socket] Connecting {}:{} (SSL/TLS)", host, port);
        SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: true,
        }
    }

    pub fn read_line(&self) -> String {
        
        format!("+OK server@{}:{} ready", self.host, self.port)
    }

    pub fn write_line(&self, data: String) {
        println!("[Socket {}:{}] >> {}", self.host, self.port, data);
    }

    pub fn send_command(&self, cmd: &str) {
        println!("[Socket {}:{}] >> {}", self.host, self.port, cmd);
    }
}
