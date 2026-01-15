//! Test utils
use rand::{Rng, distr::Alphanumeric};

#[allow(dead_code)]
pub(crate) fn random_string(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
