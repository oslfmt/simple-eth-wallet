use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;

use bip32::{XPrv, XPub, ChildNumber, DerivationPath, Prefix};
use bip32::secp256k1::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Serialize, Deserialize};

use crate::crypto::{generate_eth_address, keccak512};
use crate::utils;

#[derive(Serialize, Deserialize)]
// A more appropriate name is WalletData
// TODO: I think a better structure is having WalletData have a TempData struct in it
pub struct UserData {
    /// Encoded wallet seed
    pub pad: Vec<u8>,
    /// The key used to verify logins
    pub verification_key: Vec<u8>
}

impl UserData {
    /// Creates new UserData struct with given pad and verification_key
    pub fn new(pad: Vec<u8>, verification_key: XPub) -> Self {
        UserData { pad, verification_key: verification_key.to_bytes().to_vec() }
    }

    /// Stores the key user data that is necessary for logging in again
    pub fn store(&self) -> Result<(), String> {
        let mut file = File::create("userdata.txt").unwrap();
        let data_bytes = serde_json::to_vec(self).unwrap();

        match file.write_all(&data_bytes) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("Error writing to file: {}", e)),
        }
    }

    pub fn verify_password(&self, password: String) -> bool {
        let password_hash = keccak512(password.as_bytes());
        let seed = utils::xor(&password_hash, &self.pad).unwrap();
        let (_, xpub) = UserData::create_keys_from_path(&seed, "m/44'/60'/0'");

        if xpub.to_bytes().to_vec() == self.verification_key {
            true
        } else {
            false
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
}

// The index of the account in the vector serves as the account number
pub struct TempData {
    /// The parent private key deriving all accounts
    pub deriving_key: XPrv,
    /// A vector of derived accounts
    pub accounts: Vec<Account>,
}

impl TempData {
    /// Instantiates TempData struct with the deriving key, which will be used to derive all child accounts
    pub fn new(deriving_key: XPrv) -> Self {
        TempData {
            deriving_key,
            accounts: vec![]
        }
    }

    /// Creates a new account using the deriving key stored in TempData, with specified index
    /// and adds the created account to the TempData vector
    /// Returns a clone of the created account
    pub fn create_account(&mut self, index: usize) -> Account {
        let account = Account::new(&self.deriving_key, index);
        self.accounts.push(account.clone());
        account
    }

    /// Returns a clone of the first account of the accounts vector
    pub fn default_account(&self) -> Account {
        self.accounts[0].clone()
    }

    /// Prints all the accounts associated with user
    pub fn print_accounts(&self) {
        for (index, acc) in self.accounts.iter().enumerate() {
            println!("{}) {}", index, acc.address);
        }
    }

    pub fn get_account(&self, index: usize) -> Account {
        self.accounts[index].clone()
    }
}

#[derive(Clone)]
pub struct Account {
    pub nonce: u64,
    prv_key: Vec<u8>,
    pub address: String,
}

impl Account {
    /// Creates a new address within the wallet using HD wallet functionality
    /// deriving_key - the parent key with path m/44'/60'/0'/0, used to derive all child accounts
    /// index - the index of the child account
    ///
    /// The returned key has path: m/44'/60'/0'/0/x, where x = 0,1,2,3...
    pub fn new(deriving_key: &XPrv, index: usize) -> Self {
        let child_xprv = deriving_key.derive_child(ChildNumber::new(index as u32, false).unwrap()).unwrap();
        let child_xpub = child_xprv.public_key();

        // Convert default acct pub_key to Ethereum address by taking hash of UNCOMPRESSED point
        let pub_key: [u8; 65] = child_xpub.public_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        // only hash last 64B of pub_key because we want to leave out the prefix 0x04
        let addr_bytes = generate_eth_address(&pub_key[1..]);
        let address = String::from("0x") + &hex::encode(addr_bytes);

        Account {
            nonce: 0,
            prv_key: child_xprv.to_bytes().to_vec(),
            address,
        }
    }

    /// Returns a reference to the private key associated with the account
    pub fn private_key(&self) -> &[u8] {
        &self.prv_key
    }
}

