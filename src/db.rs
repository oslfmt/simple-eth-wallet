use rocksdb::{DB};

/// Opens DB instance at specified path, creating a new one if non-existent
pub fn open_db(path: &str) -> DB {
    DB::open_default(path).unwrap()
}