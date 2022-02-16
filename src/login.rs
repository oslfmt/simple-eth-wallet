use crate::utils;

pub fn get_username_password() -> (String, String) {
    println!("{}", "Enter Username: ");
    let username = utils::read_user_input();
    println!("{}", "Enter Password: ");
    let password = utils::read_user_input();

    (username, password)
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