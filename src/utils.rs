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
pub fn xor(a: &[u8], b: &[u8]) -> Result<[u8; usize], String> {
    if a.len() == b.len() {
        const length: usize = a.len();
        let mut result: [u8; length] = [u8; length];

        for i in 0..32 {
            result[i] = a[i] ^ b[i];
        }

        Ok(result)
    } else {
        Err(String::from("Byte arrays must be same length"))
    }
}