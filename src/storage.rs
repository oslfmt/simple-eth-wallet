use std::fs::File;
use std::io::prelude::*;

use bip32::{XPrv, XPub, ChildNumber, DerivationPath, Prefix};
use bip32::secp256k1::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Serialize, Deserialize};

use crate::crypto::generate_eth_address;

#[derive(Serialize, Deserialize)]
pub struct UserData {
    pad: Vec<u8>,
    /// the key used to verify logins
    verification_key: Vec<u8>
}

// The index of the account in the vector serves as the account number
pub struct TempData {
    /// The parent private key deriving all accounts
    pub deriving_key: XPrv,
    /// A vector of derived accounts
    pub accounts: Vec<Account>,
}

#[derive(Clone)]
pub struct Account {
    pub nonce: u64,
    pub prv_key: Vec<u8>,
    pub address: String,
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
    pub fn create_account(&mut self, index: u32) -> Account {
        let account = Account::new(&self.deriving_key, index);
        self.accounts.push(account.clone());
        account
    }

    /// Returns a clone of the first account of the accounts vector
    pub fn default_account(&self) -> Account {
        self.accounts[0].clone()
    }
}

impl Account {
    /// Creates a new address within the wallet using HD wallet functionality
    /// deriving_key - the parent key with path m/44'/60'/0'/0, used to derive all child accounts
    /// index - the index of the child account
    ///
    /// The returned key has path: m/44'/60'/0'/0/x, where x = 0,1,2,3...
    pub fn new(deriving_key: &XPrv, index: u32) -> Self {
        let child_xprv = deriving_key.derive_child(ChildNumber::new(index, false).unwrap()).unwrap();
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
}

impl UserData {
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
}