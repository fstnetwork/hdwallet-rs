//! # Module to generate private key from HD path
//! according to the [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//!

use bitcoin::network::constants::Network;
pub use bitcoin::util::bip32::ChildNumber::{self, Hardened, Normal};
use bitcoin::util::bip32::ExtendedPrivKey;
use ethsign::SecretKey;
use regex::Regex;
use secp256k1::Secp256k1;
use std::ops;

use super::error::{Error, ErrorKind};

lazy_static! {
    static ref HD_PATH_RE: Regex = Regex::new(r#"^m/{1}[^0-9'/]*"#).unwrap();
}

/// HD path according to BIP32
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HDPath(pub Vec<ChildNumber>);

const PRIVATE_KEY_BYTES: usize = 32;

impl HDPath {
    /// Parse HD derivation path into `ChildNumber` array
    /// Accepting path in format specified by BIP32
    ///
    /// # Arguments:
    ///
    /// * path - path string
    ///
    pub fn try_from(path: &str) -> Result<Self, Error> {
        let mut res: Vec<ChildNumber> = vec![];

        if !HD_PATH_RE.is_match(path) {
            return Err(Error::from(ErrorKind::HDWalletError(
                "Invalid HD path format".to_string(),
            )));
        }

        let (_, raw) = path.split_at(2);
        for i in raw.split('/') {
            let mut s = i.to_string();

            let mut is_hardened = false;
            if s.ends_with('\'') {
                is_hardened = true;
                s.pop();
            }

            match s.parse::<u32>() {
                Ok(v) => {
                    if is_hardened {
                        res.push(Hardened(v))
                    } else {
                        res.push(Normal(v))
                    }
                }
                Err(e) => {
                    return Err(Error::from(ErrorKind::HDWalletError(format!(
                        "Invalid HD path child index: {}",
                        e.to_string()
                    ))));
                }
            };
        }

        Ok(HDPath(res))
    }
}

impl ops::Deref for HDPath {
    type Target = [ChildNumber];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Generate `Secret` using BIP32
///
///  # Arguments:
///
///  * path - key derivation path
///  * seed - seed data for master node
///
pub fn generate_keypair(path: &HDPath, seed: &[u8]) -> Result<SecretKey, Error> {
    let secp = Secp256k1::new();
    let sk = ExtendedPrivKey::new_master(&secp, Network::Bitcoin, seed)
        .and_then(|k| ExtendedPrivKey::from_path(&secp, &k, path))?;

    match SecretKey::from_raw(&{
        let mut bytes: [u8; 32] = Default::default();
        bytes.copy_from_slice(&sk.secret_key[0..PRIVATE_KEY_BYTES]);
        bytes
    }) {
        Ok(secret) => Ok(secret),
        Err(err) => Err(Error::from(ErrorKind::Secp256k1Error(format!("{:?}", err)))),
    }
}

#[cfg(test)]
mod test {
    use ethereum_types::Address;
    use hex::FromHex;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn parse_hdpath() {
        let parsed = HDPath::try_from("m/44'/60'/160720'/0'").unwrap();
        let exp = HDPath(vec![
            Hardened(44),
            Hardened(60),
            Hardened(160720),
            Hardened(0),
        ]);

        assert_eq!(parsed, exp)
    }

    #[test]
    fn test_key_generation() {
        let seed = Vec::from_hex(
            "b15509eaa2d09d3efd3e006ef42151b3\
             0367dc6e3aa5e44caba3fe4d3e352e65\
             101fbdb86a96776b91946ff06f8eac59\
             4dc6ee1d3e82a42dfe1b40fef6bcc3fd",
        )
        .unwrap();

        let path = vec![
            Hardened(44),
            Hardened(60),
            Hardened(160720),
            Hardened(0),
            Normal(0),
        ];

        let priv_key = generate_keypair(&HDPath(path), &seed).unwrap();
        assert_eq!(
            Address::from_str("79B9E1af57Ebb2600a134e28eA05e52A312957A6").unwrap(),
            Address::from(priv_key.public().address().clone())
        );
    }
}
