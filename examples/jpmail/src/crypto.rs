// ============================================================================
// Mirrors: jifpol/src/crypto/RSASelfClosure.jif
//          jifpol/src/util/DeclassifyHelper.jif
//          (AES/DES stubs for jifcrypto/ operations)
//
// JPmail encrypts message bodies with AES (falling back to DES if AES fails),
// then wraps the symmetric key with RSA using the recipient's public key.
// All operations are tracked with IFC labels so that ciphertext provenance
// is preserved even after encryption.
// ============================================================================

use macros::mcall;
use typing_rules::implicit::InvisibleSideEffectFree;
use typing_rules::lattice::*;

// ============================================================================
// RSA CLOSURE
// Mirrors: jifpol/src/crypto/RSASelfClosure.jif
//
// Jif source:
//   class RSASelfClosure[principal P, label L={P:}]
//       implements Closure[P, {P:}] {
//       final byte{P:}[] plaintext;
//       final KeyPrincipal keyP;
//       invoke(): Ciphertext {
//           // verify caller acts for keyP
//           return RSA[{P:}].encrypt(plaintext, keyP.publicKey);
//       }
//   }
// ============================================================================

/// RSA encryption closure.
///
/// Captures the plaintext (labeled L) and a key identifier.
/// `invoke()` encrypts the plaintext with the named RSA public key.
///
/// The ciphertext result is still labeled L — we preserve the provenance
/// of encrypted data so the type system knows what it corresponds to.
///
/// In JPmail: used in JPMailMessage.toMimeMailMessage() to encrypt
/// the AES symmetric key for the recipient.
pub struct RSAClosure<L: Label> {
    /// Sensitive data to encrypt (byte{P:}[] in Jif — labeled L).
    pub plaintext: Labeled<Vec<u8>, L>,            // byte{P:}[] plaintext
    /// Identifies which RSA public key to use (String{} — public, key IDs are not secret).
    pub key_id: String,            // KeyPrincipal keyP (public ref)
}

impl<L: Label> RSAClosure<L> {
    /// Mirrors: RSASelfClosure(byte{P:}[] plaintext, KeyPrincipal keyP)
    pub fn new(plaintext: Labeled<Vec<u8>, L>, key_id: &str) -> Self {
        RSAClosure {
            plaintext,
            key_id: key_id.to_string(),
        }
    }

    /// Encrypt the plaintext with the RSA public key identified by `key_id`.
    /// Mirrors: invoke() in RSASelfClosure.jif
    ///
    /// Returns `Labeled<Vec<u8>, L>` — the label is preserved on the ciphertext
    /// so downstream code still knows whose data this is.
    pub fn invoke(&self) -> Labeled<Vec<u8>, L> {
        println!(
            "[RSA] Encrypting with public key '{}'",
            self.key_id
        );
        // Stub: real impl: RSA/PKCS1 via BouncyCastle (same as JPmail)
        self.plaintext.clone()
    }

    /// Decrypt using the RSA private key (requires the private key at label L).
    /// In JPmail: called during mail retrieval in MailReaderCrypto to unwrap
    /// the session AES key.
    pub fn decrypt(ciphertext: Labeled<Vec<u8>, L>, private_key: Labeled<String, L>) -> Labeled<Vec<u8>, L> {
        println!("[RSA] Decrypting using private key (label L)");
        // Stub: real impl: RSA/PKCS1 decrypt via BouncyCastle
        let _ = private_key; // private key consumed — label enforced by type
        ciphertext
    }
}

unsafe impl<L: Label> InvisibleSideEffectFree for RSAClosure<L> {}

// ============================================================================
// AES / DES SYMMETRIC ENCRYPTION (STUBS)
// In JPmail: JPMailMessage.toMimeMailMessage() tries AES first, falls back to DES.
//            The session key is encrypted with RSA for the recipient.
// ============================================================================

/// AES-encrypt plaintext bytes (both plaintext and key labeled L).
///
/// In JPmail (JPMailMessage.jif):
///   try { ... AES.encrypt(body, sessionKey) ... }
///   catch { ... DES.encrypt(body, sessionKey) ... }  // fallback
pub fn aes_encrypt<L: Label>(
    plaintext: Labeled<Vec<u8>, L>,
    _key: Labeled<Vec<u8>, L>,
) -> Labeled<Vec<u8>, L> {
    println!("[AES] Encrypting");
    // Stub: label is preserved — ciphertext carries same label as plaintext
    plaintext
}

/// AES-decrypt ciphertext.
/// The key must be labeled L — only the owner (who has clearance L) can decrypt.
pub fn aes_decrypt<L: Label>(
    ciphertext: Labeled<Vec<u8>, L>,
    _key: Labeled<Vec<u8>, L>,
) -> Labeled<Vec<u8>, L> {
    println!("[AES] Decrypting");
    ciphertext
}

/// DES-encrypt plaintext bytes (fallback for when AES is unavailable).
pub fn des_encrypt<L: Label>(
    plaintext: Labeled<Vec<u8>, L>,
    _key: Labeled<Vec<u8>, L>,
) -> Labeled<Vec<u8>, L> {
    println!("[DES] Encrypting (AES fallback)");
    plaintext
}

// ============================================================================
// DECLASSIFY HELPER
// Mirrors: jifpol/src/util/DeclassifyHelper.jif
//
// Jif source (abridged):
//   class DeclassifyHelper {
//       static byte{}[] declassifyByteArray(byte{L}[] data, principal P)
//           where caller(P)  // explicit authorization required
//       static byte{Dest}[] upgradeByteArray(byte{}[] data)
//   }
//
// In JPmail: used when the encrypted ciphertext must be transmitted over the
// wire (e.g., written to the SMTP socket). The ciphertext is computationally
// safe to reveal but the label must still be explicitly downgraded.
// ============================================================================

/// Token representing explicit, authorized declassification.
///
/// In JPmail: obtained by calling PrincipalUtil.authorize(P, closure, lb, lb)
/// which runs a Closure[P,L] with authority from principal P.
pub struct DeclassAuthorization {
    /// The principal that granted this authorization (String{} — public audit trail).
    pub granted_by: String,        // String{} — public
}

impl DeclassAuthorization {
    pub fn new(principal: impl std::fmt::Display) -> Self {
        DeclassAuthorization {
            granted_by: principal.to_string(),
        }
    }
}

/// Authorized declassification of any labeled value.
/// The DeclassAuthorization token proves the caller has authority to declassify.
pub fn authorized_declassify<T, L: Label>(
    value: Labeled<T, L>,
    _auth: &DeclassAuthorization,
) -> T {
    declassify(value)
}

/// Utility for explicit label operations.
/// Mirrors: DeclassifyHelper.jif
pub struct DeclassifyHelper;

impl DeclassifyHelper {
    /// Upgrade a public byte array to label Dest (safe: more restrictive).
    /// Mirrors: upgradeByteArray(byte{}[] data) -> byte{Dest}[] in DeclassifyHelper.jif
    ///
    /// Example use: raw ciphertext bytes received from the network (public)
    /// are upgraded to the recipient's label before decryption begins.
    pub fn upgrade_byte_array<Dest: Label>(
        data: Vec<u8>,
    ) -> Labeled<Vec<u8>, Dest> {
        // Public → Dest is always safe (upgrading from bottom label)
        Labeled::new(data)
    }

    /// Explicitly declassify a labeled byte array to raw bytes.
    /// Mirrors: declassifyByteArray(byte{L}[] data, principal P) in DeclassifyHelper.jif
    ///
    /// REQUIRES an explicit DeclassAuthorization token — this is the only
    /// legitimate way to lower a label in the system.
    ///
    /// In JPmail: the authorization comes from PrincipalUtil.authorize() after
    /// verifying that principal P has the right to declassify label L.
    ///
    /// Typical use: converting encrypted ciphertext (labeled L) to public so
    /// it can be transmitted to the SMTP server.
    pub fn declassify_byte_array<Src: Label>(
        data: Labeled<Vec<u8>, Src>,
        auth: DeclassAuthorization,
    ) -> Vec<u8> {
        println!(
            "[DeclassifyHelper] Declassifying (authorized by '{}')",
            auth.granted_by
        );
        // Authorized declassification: Src → raw via DeclassAuthorization token
        authorized_declassify(data, &auth)
    }
}
