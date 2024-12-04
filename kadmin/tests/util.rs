//! Test utils
use rand::{Rng, distributions::Alphanumeric};

#[allow(dead_code)]
pub(crate) fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
