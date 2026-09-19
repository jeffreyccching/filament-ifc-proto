// ============================================================================
// Mirrors: jifpol/src/util/Password.jif
//          jpmail/src/util/NewPassword.jif
//
// Password.jif stores SMTP and POP3 credentials encrypted with DES on disk.
// In the JPmail demo:
//   demo/password-pop3      — encrypted POP3 password
//   demo/password-pop3_iv   — DES IV
//   demo/password-pop3_key  — DES key
//   demo/password-smtp      — encrypted SMTP password
//   (same pattern for alice, bob, bono under demo/passwd-{name}/)
//
// The plaintext password is char{L}[] in Jif — labeled at the owner's level.
// Only code running at clearance L can read or use the decrypted password.
// ============================================================================

use typing_rules::lattice::*;

// ============================================================================
// PASSWORD
// Mirrors: jifpol/src/util/Password.jif
//
// Jif source (abridged):
//   class Password[label L] {
//       private static final int MAX_PWD_LEN = 50;
//       char{L}[] getPassword(String encFile, String ivFile, String keyFile)
//       void setPassword(char{L}[] pwd, String encFile, String ivFile, String keyFile)
//       String{} toString64(byte[] data)  // Base64 helper
//   }
// ============================================================================

/// Manages an encrypted credential stored on disk.
///
/// The type parameter L is the security label of the plaintext password.
/// `get_password()` returns `Labeled<String, L>` — the decrypted value
/// cannot leave the owner's security context without explicit declassification.
///
/// In the JPmail demo, per-user password files live under `demo/passwd-{name}/`.
pub struct Password<L: Label> {
    /// Path to the DES-encrypted password ciphertext (String{} — public, path is not secret).
    pub encrypted_file: String,    // String{} — public
    /// Path to the DES initialisation vector (String{} — public).
    pub iv_file: String,           // String{} — public
    /// Path to the DES key file (String{} — public, but key data inside is sensitive).
    pub key_file: String,          // String{} — public
    /// Phantom marker tying this handle to security label L.
    _label: std::marker::PhantomData<L>,
}

impl<L: Label> Password<L> {
    /// Create a password handle pointing to the encrypted files under `base_path`.
    ///
    /// In JPmail: `base_path` corresponds to the per-user directory, e.g.
    ///   "demo/passwd-alice/"  for the alice principal
    ///   "demo/"               for the global SMTP/POP3 passwords
    pub fn new(base_path: &str) -> Self {
        Password {
            encrypted_file: format!("{}password", base_path),
            iv_file: format!("{}password_iv", base_path),
            key_file: format!("{}password_key", base_path),
            _label: std::marker::PhantomData,
        }
    }

    /// Read and decrypt the password.
    /// Mirrors: getPassword() in Password.jif
    ///
    /// In JPmail: reads `encrypted_file`, decrypts with DES using `key_file` and
    /// `iv_file`, trims to MAX_PWD_LEN=50 chars, returns char{L}[].
    ///
    /// Returns `Labeled<String, L>` — the plaintext stays labeled at level L.
    /// Code operating below clearance L (e.g. bono) cannot access the value.
    pub fn get_password(&self) -> Labeled<String, L> {
        println!(
            "[Password] Reading encrypted credential from '{}'",
            self.encrypted_file
        );
        // Stub: real impl reads encrypted_file, decrypts with DES, returns plaintext
        Labeled::new(format!("[decrypted_from:{}]", self.encrypted_file))
    }

    /// Encrypt and store the password to disk.
    /// Mirrors: setPassword(char{L}[] pwd, ...) in Password.jif
    ///
    /// In JPmail: generates a random DES key + IV, encrypts `pwd`, writes
    /// three files: encrypted ciphertext, IV, and key.
    ///
    /// Takes `Labeled<String, L>` — only code at clearance L can call this,
    /// because providing the argument requires holding a Labeled<_, L> value.
    pub fn set_password(&self, pwd: Labeled<String, L>) {
        println!(
            "[Password] Storing encrypted credential to '{}'",
            self.encrypted_file
        );
        // Stub: real impl generates DES key/IV, encrypts pwd.value, writes files
        drop(pwd);
    }

    /// Base64-encode a byte slice.
    /// Mirrors: toString64(byte[] data) in Password.jif (a private helper).
    pub fn to_base64(data: &[u8]) -> String {
        // Stub: in real impl uses Sun Base64 encoder (same as JPmail)
        format!("[base64:{}bytes]", data.len())
    }
}

// ============================================================================
// NEW PASSWORD
// Mirrors: jpmail/src/util/NewPassword.jif
//
// Jif source (main method):
//   principal{} user = ...
//   if ("-".equals(args[0])) {
//       // bootstrap mode: use provided password directly
//   } else {
//       // policy mode: verify "me actsfor user" delegation,
//       //              then call password.setPassword(...)
//   }
// ============================================================================

/// Bootstraps an encrypted password file for a principal.
///
/// In JPmail, this is run once during setup:
///   make util/NewPassword ARGS='alice mypassword'
///
/// It verifies the delegation chain ("me actsfor alice") before writing.
pub struct NewPassword;

impl NewPassword {
    /// Bootstrap a new encrypted password for the named principal.
    ///
    /// In JPmail: verifies principal delegation, creates Password object for the
    /// user's demo directory, calls set_password() with the plaintext.
    ///
    /// The `plaintext` argument is `Labeled<String, L>` — only code that
    /// already holds clearance L can supply it, preventing privilege escalation.
    pub fn bootstrap<L: Label>(username: &str, plaintext: Labeled<String, L>) {
        println!(
            "[NewPassword] Bootstrapping encrypted credential for principal '{}'",
            username
        );
        println!(
            "[NewPassword] Verifying delegation: 'me actsFor {}' ...",
            username
        );
        // Stub: real impl calls PrincipalUtil.authorize() with an AddDelClosureL
        let pw = Password::<L>::new(&format!("demo/passwd-{}/", username));
        pw.set_password(plaintext);
        println!("[NewPassword] Done — password file written.");
    }
}
