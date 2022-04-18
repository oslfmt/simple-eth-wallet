use std::io;
use std::str::FromStr;

use thiserror::Error;
use bip32::{ChildNumber, XPrv, XPub, DerivationPath};

#[derive(Error, Debug)]
pub enum AddressParseError {
    #[error("Invalid hex character")]
    InvalidHexCharacter,
    #[error("Invalid address length")]
    InvalidLength,
}

/// Returns clean (no newline) user input
pub fn read_user_input() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    if let Some('\n') = input.chars().next_back() {
        input.pop();
    }
    input
}

pub fn wei_to_eth(amount: u128) -> String {
    (amount as f64 / 10_f64.powf(18 as f64)).to_string()
}

/// Converts an ETH amount to corresponding wei amount.
/// NOTE: any wei amount less than 1 is invalid and will truncate to 0
pub fn eth_to_wei(amount: f64) -> u128 {
    (amount * 10_f64.powf(18 as f64)) as u128
}

/// Returns the XOR of two byte arrays. The byte arrays must be the same length
pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
    if a.len() == b.len() {
        let mut result = vec![];
        for i in 0..a.len() {
            result.push(a[i] ^ b[i]);
        }
        Ok(result)
    } else {
        Err(String::from("Byte arrays must be same length"))
    }
}

/// Generate the key pair from a given path
pub fn create_keys_from_path(seed: &[u8], path: &str) -> (XPrv, XPub) {
    let child_xprv = XPrv::derive_from_path(
        seed,
        &DerivationPath::from_str(path).unwrap()
    ).unwrap();
    let child_xpub = child_xprv.public_key();
    (child_xprv, child_xpub)
}

pub fn derive_child_secret_key(parent_key: &XPrv, index: u32) -> [u8; 32] {
    let child = parent_key.derive_child(ChildNumber::new(index, false).unwrap()).unwrap();
    child.to_bytes()
}

pub fn get_valid_address_bytes() -> (String, [u8; 20]) {
    loop {
        println!("Enter recipient address: ");
        let recipient = read_user_input();

        match sanitize_address(recipient.clone()) {
            Ok(recipient_bytes) => return (recipient, recipient_bytes),
            Err(e) => {
                // TODO: prints raw enum variant, not error message
                println!("{:?}", e);
                continue
            },
        }
    }
}

// TODO: figure out a cleaner way to do this
fn sanitize_address(address: String) -> Result<[u8; 20], AddressParseError> {
    let raw_address = match address.strip_prefix("0x") {
        Some(r) => r,
        None => &address,
    };

    match hex::decode(raw_address) {
        Ok(bytes) => {
            match vec_to_array::<u8, 20>(bytes) {
                Ok(r) => Ok(r),
                Err(_e) => Err(AddressParseError::InvalidLength)
            }
        },
        Err(_e) => Err(AddressParseError::InvalidHexCharacter),
    }
}

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N], String> {
    v.try_into()
        .map_err(|e| format!("Invalid length"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
/*    #[test_case(1.0 => 1000000000000000000 ; "a whole number eth amount")]
    #[test_case(1.35 => 1350000000000000000 ; "a fractional eth amount")]
    #[test_case(0.00000000000000000001 => 0 ; "an eth amount smaller than 1 wei")]*/
    fn test_eth_to_wei_1() {
        let amount = 1.0;
        let result = eth_to_wei(amount);
        let expected: u128 = 1000000000000000000;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_eth_to_wei_2() {
        let amount = 1.35;
        let result = eth_to_wei(amount);
        let expected: u128 = 1350000000000000000;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_eth_to_wei_3() {
        let amount = 0.00000000000000000001;
        let result = eth_to_wei(amount);
        let expected: u128 = 0;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_eth_to_wei_4() {
        let amount = 0.00000000000000000099;
        let result = eth_to_wei(amount);
        let expected: u128 = 0;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sanitize_address() {
        let address = String::from("0x73363901CD60Ace0Df1df46111fA999416Bb9Bd1");
        let result = sanitize_address(address).unwrap();
        let expected: [u8; 20] = hex::decode("73363901CD60Ace0Df1df46111fA999416Bb9Bd1").unwrap().try_into().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_xor() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        let c = xor(&a, &b).unwrap();
        assert_eq!(c, [0u8; 32].to_vec());

        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = xor(&a, &b).unwrap();
        assert_eq!(c, [0u8; 32].to_vec());

        let a = [39,2,45,32,9,10];
        let b = [40,5,34,11,2,56];
        let c = xor(&a, &b).unwrap();
        let a_return = xor(&b, &c).unwrap();
        assert_eq!(a, a_return.as_slice());
    }

    #[test]
    #[should_panic(expected = "Byte arrays must be same length")]
    fn test_xor_failure() {
        let a = [0u8; 32];
        let b = [0u8; 31];
        let c = xor(&a, &b).unwrap();
    }
}