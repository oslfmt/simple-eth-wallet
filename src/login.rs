use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{BufRead};

/// Reads in username, password pairs from a file and returns a hashmap with the stored pairs
pub fn create_map_from_file(login_file: File) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    if let lines = io::BufReader::new(login_file).lines() {
        for line in lines {
            if let Ok(ip) = line {
                // read up to the space delimiter and store result in username
                let v: Vec<&str> = ip.split(' ').collect();
                map.insert(v[0].to_string(), v[1].to_string());
            }
        }
    }
    map
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_no_duplicate_usernames() {

    }

    #[test]
    fn test_something() {

    }
}