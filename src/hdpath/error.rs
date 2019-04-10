//! # `HDWallet` Keystore files (UTC / JSON) module errors

use bitcoin::util::bip32;

error_chain! {
    foreign_links {
        StdIo(std::io::Error);
        Bip32(bip32::Error);
        Secp256k1(secp256k1::Error);
        EthSign(ethsign::Error);
    }

    errors {
        HDWalletError(s: String) {
            description("HD Wallet Keystore file error")
            display("HD Wallet error: {}", s)
        }
        Secp256k1Error(s: String) {
            description("Secp256k1 error")
            display("Secp256k1 error: {}", s)
        }
    }
}
