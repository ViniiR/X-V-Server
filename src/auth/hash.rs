use argon2::{hash_encoded, verify_encoded, Config};
use rand::{thread_rng, RngCore};

pub async fn hash_str(str: &str) -> Result<String, ()> {
    let str = str.as_bytes();
    let argon2 = Config::default();
    let mut salt: [u8; 32] = [0; 32];

    thread_rng().fill_bytes(&mut salt);

    match hash_encoded(&str, &salt, &argon2) {
        Ok(s) => Ok(s),
        Err(..) => Err(()),
    }
}

pub async fn compare_password(password: &str, hash: &str) -> bool {
    match verify_encoded(hash, password.as_bytes()) {
        Ok(..) => true,
        Err(..) => false,
    }
}
