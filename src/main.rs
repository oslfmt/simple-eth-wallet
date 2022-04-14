mod crypto;
mod utils;
mod storage;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use crate::utils::{read_user_input};
use crate::storage::Wallet;

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
            println!("{}", "Enter Password: ");
            let password = read_user_input();
            let mut wallet = Wallet::from(password);
            wallet.run();
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
            let mut stored_wallet: Wallet = serde_json::from_str(&buf).unwrap();

            loop {
                println!("{}", "Enter Password: ");
                let password = read_user_input();

                match stored_wallet.verify_password(password) {
                    true => {
                        stored_wallet.run();
                        return
                    },
                    false => println!("Incorrect password"),
                };
            }
        },
        2 => {
            println!("{}", "Enter Password: ");
            let password = read_user_input();
            let mut wallet = Wallet::from(password);
            wallet.run();
        },
        _ => println!("{}", "Invalid option"),
    }
}
