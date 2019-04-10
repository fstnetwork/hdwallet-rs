//! # Keystore files pseudo-random functions
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use scrypt::{scrypt, ScryptParams};
use sha2::{Sha256, Sha512};

/// `HMAC_SHA256` pseudo-random function name
pub const HMAC_SHA256_PRF_NAME: &str = "hmac-sha256";

/// `HMAC_SHA512` pseudo-random function name
pub const HMAC_SHA512_PRF_NAME: &str = "hmac-sha512";

/// Pseudo-Random Functions (PRFs)
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prf {
    /// HMAC-SHA-256 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha256")]
    HmacSha256,

    /// HMAC-SHA-512 (specified in (RFC 4868)[https://tools.ietf.org/html/rfc4868])
    #[serde(rename = "hmac-sha512")]
    HmacSha512,
}

impl Prf {
    /// Calculate hashed message authentication code using SHA-256 digest
    pub fn hmac(&self, passphrase: &str) -> Hmac<Sha256> {
        Hmac::new_varkey(passphrase.as_bytes()).expect("HMAC accepts all key sizes")
    }

    /// Calculate hashed message authentication code using SHA-512 digest
    pub fn hmac512(&self, passphrase: &str) -> Hmac<Sha512> {
        Hmac::new_varkey(passphrase.as_bytes()).expect("HMAC accepts all key sizes")
    }
}

impl Default for Prf {
    fn default() -> Self {
        Prf::HmacSha256
    }
}

/// `PBKDF2` key derivation function name
pub const PBKDF2_KDF_NAME: &str = "pbkdf2";

/// `Scrypt` key derivation function name
pub const SCRYPT_KDF_NAME: &str = "scrypt";

/// Derived core length in bytes (by default)
pub const DEFAULT_DK_LENGTH: usize = 32;

/// Key derivation function salt length in bytes
pub const KDF_SALT_BYTES: usize = 32;

pub type Salt = [u8; KDF_SALT_BYTES];

/// Key derivation function parameters
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Key derivation function
    #[serde(flatten)]
    pub kdf: Kdf,

    /// `Kdf` length for parameters
    pub dklen: usize,

    /// Cryptographic salt for `Kdf`
    pub salt: Salt,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            kdf: Kdf::default(),
            dklen: DEFAULT_DK_LENGTH,
            salt: Salt::default(),
        }
    }
}

/// Security level for `Kdf`
#[derive(Clone, Copy, Debug)]
pub enum KdfDepthLevel {
    /// Security level used by default
    Normal = 1024,

    /// Advanced security level
    High = 8096,

    /// Top security level (consumes more CPU time)
    Ultra = 262_144,
}

impl Default for KdfDepthLevel {
    fn default() -> Self {
        KdfDepthLevel::Normal
    }
}

/// Key derivation function
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kdf {
    /// PBKDF2 (not recommended, specified in (RFC 2898)[https://tools.ietf.org/html/rfc2898])
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        /// Pseudo-Random Functions (`HMAC-SHA-256` by default)
        prf: Prf,

        /// Number of iterations (`262144` by default)
        c: u32,
    },

    /// Scrypt (by default, specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])
    #[serde(rename = "scrypt")]
    Scrypt {
        /// Number of iterations (`19201` by default)
        n: u32,

        /// Block size for the underlying hash (`8` by default)
        r: u32,

        /// Parallelization factor (`1` by default)
        p: u32,
    },
}

impl Kdf {
    /// Derive fixed size key for given salt and passphrase
    pub fn derive(&self, len: usize, kdf_salt: &[u8], passphrase: &str) -> Vec<u8> {
        let mut key = vec![0u8; len];

        match *self {
            Kdf::Pbkdf2 { prf, c } => {
                match prf {
                    Prf::HmacSha256 => {
                        // let mut hmac = prf.hmac(passphrase);
                        pbkdf2::<Hmac<Sha256>>(
                            passphrase.as_bytes(),
                            kdf_salt,
                            c as usize,
                            &mut key,
                        );
                    }
                    Prf::HmacSha512 => {
                        pbkdf2::<Hmac<Sha512>>(
                            passphrase.as_bytes(),
                            kdf_salt,
                            c as usize,
                            &mut key,
                        );
                    }
                };
            }
            Kdf::Scrypt { n, r, p } => {
                let log_n = (n as f64).log2().round() as u8;
                let params = ScryptParams::new(log_n, r, p).expect("Invalid Scrypt parameters");
                scrypt(passphrase.as_bytes(), kdf_salt, &params, &mut key).expect("Scrypt failed");
            }
        }

        key
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf::Scrypt {
            n: 1024,
            r: 8,
            p: 1,
        }
    }
}
