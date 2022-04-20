mod crypto;
mod utils;
mod storage;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use crate::utils::{read_user_input};
use crate::storage::Wallet;
use bip39::{Mnemonic, Language};

// TODO: in case of ctrl+c, need to write data cleanly to file, or else things like nonce won't be updated
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
            let mut wallet = Wallet::new(password);
            wallet.run();
        },
        2 => {
            import_and_run_wallet();
        },
        _ => println!("{}", "Invalid option"),
    }
}

fn display_menu_two() {
    loop {
        println!("1) Login");
        println!("2) Import wallet");
        println!("3) QUIT");
        match read_user_input().parse::<u8>() {
            Ok(option) => {
                match option {
                    1 => {
                        let mut file = File::open("./userdata.txt").unwrap();
                        let mut buf = String::new();
                        file.read_to_string(&mut buf).unwrap();
                        let mut stored_wallet: Wallet = serde_json::from_str(&buf).unwrap();

                        loop {
                            println!("Enter Password (or type q to return to main menu): ");
                            let user_input = read_user_input();

                            if user_input == "q" {
                                break;
                            } else {
                                match stored_wallet.verify_password(user_input) {
                                    true => {
                                        stored_wallet.run();
                                        return
                                    },
                                    false => println!("Incorrect password"),
                                };
                            }
                        }
                    },
                    2 => import_and_run_wallet(),
                    3 => return,
                    _ => println!("{}", "Invalid option"),
                }
            },
            Err(_e) => {
                println!("Invalid option. Please enter 1 or 2.");
            },
        }
    };
}

fn import_and_run_wallet() {
    println!("{}", "Enter Password (or type q to return to main menu):");
    let password = read_user_input();
    loop {
        if &password == "q" {
            break;
        } else {
            loop {
                println!("Enter your mnemonic phrase to restore your wallet (or type q to return to main menu):");
                let phrase = utils::read_user_input();
                if phrase != "q" {
                    match Mnemonic::from_phrase(&phrase, Language::English) {
                        Ok(m) => {
                            let mut wallet = Wallet::from(password.clone(), m);
                            wallet.run();
                            break;
                        },
                        Err(_e) => println!("Bad mnemonic. Enter 12 or 24 word phrase."),
                    };
                } else {
                    break;
                };
            }
        };
        break;
    }
}
