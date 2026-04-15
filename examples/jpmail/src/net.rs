
use typing_rules::implicit::InvisibleSideEffectFree;
use typing_rules::lattice::*;

#[derive(Debug)]
pub struct SecureSocket<L: Label> {
    
    pub host: String, 
    
    pub port: u16, 
    
    pub use_ssl: bool, 
    _label: std::marker::PhantomData<L>,
}

impl<L: Label> SecureSocket<L> {
    
    pub fn create(host: impl std::fmt::Display, port: u16) -> Labeled<Self, L> {
        println!("[Socket] Connecting {}:{} (plain TCP)", host, port);
        Labeled::new(SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: false,
            _label: std::marker::PhantomData,
        })
    }

    pub fn create_ssl(host: &str, port: u16) -> Labeled<Self, L> {
        println!("[Socket] Connecting {}:{} (SSL/TLS)", host, port);
        Labeled::new(SecureSocket {
            host: host.to_string(),
            port,
            use_ssl: true,
            _label: std::marker::PhantomData,
        })
    }

    pub fn read_line(&self) -> Labeled<String, L> {
        
        Labeled::new(format!("+OK server@{}:{} ready", self.host, self.port))
    }

    pub fn write_line<Src: Label + LEQ<L>>(&self, data: Labeled<String, Src>) {
        println!("[Socket {}:{}] >> [labeled data]", self.host, self.port);
    }

    pub fn send_command(&self, cmd: &str) {
        println!("[Socket {}:{}] >> {}", self.host, self.port, cmd);
    }
}

unsafe impl<L: Label> InvisibleSideEffectFree for SecureSocket<L> {}
