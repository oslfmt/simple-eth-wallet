use rocksdb::{DB, Options};

/// Opens DB instance at specified path, creating a new one if non-existent
pub fn open_db(path: &str) -> DB {
    DB::open_default(path).unwrap()
}

/// Inserts a k-v pair into the DB
pub fn insert() {

}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_new_db() {
        let path = "db";
        create_db(path);
    }
}