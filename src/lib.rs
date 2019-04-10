#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate error_chain;

extern crate bitcoin;
extern crate ethereum_types;
extern crate ethsign;
extern crate num;
extern crate rand;
extern crate regex;
extern crate scrypt;
extern crate secp256k1;
extern crate sha2;

extern crate serde;
#[macro_use]
extern crate serde_derive;

mod error;
pub mod hdpath;
pub mod mnemonic;

pub use self::error::Error;

lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}
