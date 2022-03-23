use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use sha3::{Digest, Keccak256, Keccak512};

pub struct Secp {
    pub secp256k1: Secp256k1<secp256k1::All>,
}

impl Secp {
    pub fn new() -> Self {
        Secp { secp256k1: Secp256k1::new() }
    }

    pub fn create_keypair(&self) -> (SecretKey, PublicKey) {
        let mut rng = OsRng::new().expect("OsRng");
        self.secp256k1.generate_keypair(&mut rng)
    }

    pub fn sign_message(&self, msg: &[u8], sk: SecretKey) -> secp256k1::ecdsa::Signature {
        let message = Message::from_slice(msg).unwrap();
        self.secp256k1.sign_ecdsa(&message, &sk)
    }
}

pub fn generate_eth_address(public_key: &[u8]) -> [u8; 20] {
    let result = keccak256(public_key);
    result[12..].try_into().unwrap()
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().try_into().unwrap()
}

pub fn keccak512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Keccak512::new();
    hasher.update(input);
    hasher.finalize().try_into().unwrap()
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