mod crypto;
mod utils;
mod storage;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use crate::utils::{read_user_input, wei_to_eth, xor};
use crate::crypto::{keccak512};
use crate::storage::{Account, Wallet};

fn main() {
    println!("{}", "Starting Rwallet2.0, an HD wallet...");

    if !Path::new("./userdata.txt").exists() {
        display_menu_one();
    } else {
        display_menu_two();
    }
}

fn display_menu_one() {
    println!("{}", "1) Create a new wallet");
    println!("{}", "2) Import wallet");
    let option = read_user_input().parse::<u8>().unwrap();

    match option {
        1 => {
            println!("{}", "Enter New Password: ");
            let password = read_user_input();

            let wallet = Wallet::new(password);
            wallet.run();

            match wallet.store() {
                Ok(()) => println!("Stored wallet data safely"),
                Err(e) => println!("{}", e),
            }
        },
        2 => {
            //import_wallet();
        },
        _ => println!("{}", "Invalid option"),
    }
}

fn display_menu_two() {
    println!("{}", "1) Login");
    println!("{}", "2) Import wallet");
    let option = read_user_input().parse::<u8>().unwrap();

    match option {
        1 => {
            let mut file = File::open("./userdata.txt").unwrap();
            let mut buf = String::new();
            file.read_to_string(&mut buf).unwrap();
            let d: Wallet = serde_json::from_str(&buf).unwrap();

            loop {
                // prompt user to enter password
                println!("{}", "Enter Password: ");
                let password = read_user_input();

                // if password is correct, this will be the correct seed
                match d.verify_password(password) {
                    // TODO: need to somehow reinstantiate the temp data
                    true => println!("success"), //run_wallet(),
                    false => println!("Incorrect password"),
                }
            }
        },
        2 => {
            // TODO: check that it should overwrite current file contents
            //import_wallet();
        },
        _ => println!("{}", "Invalid option"),
    }
}

/*fn import_wallet() {
    // NOTE: importing wallet overwrites old wallet data. You can only have one wallet at any given time
    println!("Enter your mnemonic phrase to restore your wallet:\n");
    let phrase = read_user_input();
    let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");

    let master_prv_key = generate_master_prv_key(seed.as_bytes());

    // TODO: In the future, follow BIP-44 spec to generate 1 account by default. After that have option to add new accounts
    let (ext_prv_key, pub_key) = generate_default_keypair(master_prv_key);

    // create new password
    println!("{}", "Create Password: ");
    let password = read_user_input();

    let pad = xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap().to_vec();

    // TODO: to_bytes() returns SEC1-encoded, might not need first byte?
    match store_user_data(pad, pub_key.to_bytes()[1..].try_into().unwrap()) {
        Ok(()) => run_wallet_actions(ext_prv_key, pub_key.to_bytes()[1..].try_into().unwrap()),
        Err(e) => println!("{}", e),
    }
}*/

#[cfg(test)]
mod test {
    use super::*;
    use bip32::{ExtendedKey, Prefix, XPrv};

    #[test]
    fn test_vector_one_bip32() {
        let seed = hex::decode("06f8f9d1cc0ffacd3cd59686ddbe6c5e71dfbf20a4c99fdd30ad6ba2f98f1c31c12091d72ed452d361c41e09aea84c2e3076ced658f2ea92d4ba45bc97de6566").unwrap();
        let master_prv = XPrv::new(seed.clone()).unwrap();
        let master_pub = master_prv.public_key();
    }
}
