use std::io;
use rocksdb::{DB};

/// Opens DB instance at specified path, creating a new one if non-existent
pub fn open_db(path: &str) -> DB {
    DB::open_default(path).unwrap()
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

pub fn get_username_password() -> (String, String) {
    println!("{}", "Enter Username: ");
    let username = read_user_input();
    println!("{}", "Enter Password: ");
    let password = read_user_input();

    (username, password)
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

#[cfg(test)]
mod test {
    use super::*;

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