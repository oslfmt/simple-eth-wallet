use std::fs::OpenOptions;
use std::io::Write;

use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1};
use sha3::{Digest, Keccak256};
use hex;

pub fn generate_secp256k1_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    secp.generate_keypair(&mut rng)
    // store_keypair(&secret_key.serialize_secret(), &public_key.serialize_uncompressed());
}

pub fn generate_eth_address(public_key: &[u8]) -> [u8; 20] {
    let result = keccak256(public_key);
    result[12..].try_into().unwrap()
}

fn keccak256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

fn store_keypair(secret_key: &[u8], public_key: &[u8; 65]) {
    let mut file = OpenOptions::new().append(true).create(true).open("keypairs.db").unwrap();
    writeln!(file, "{}", format!("{}{}{}", hex::encode(secret_key), " ", hex::encode(public_key)));
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_PUBLIC_KEY: &str = "6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0";

    #[test]
    fn test_generate_eth_address() {
        let pk = hex::decode(TEST_PUBLIC_KEY).unwrap();
        let address = generate_eth_address(&pk);
        let expected = "001d3f1ef827552ae1114027bd3ecf1f086ba0f9";

        assert_eq!(hex::encode(address), expected);
    }
}