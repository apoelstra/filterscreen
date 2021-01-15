
use bitcoin;
use bitcoin::hashes::{sha256, hash160};
use bitcoin::hashes::hex::FromHex;
use bitcoin::consensus::Decodable;
use std::io::{self, Read};
use std::str::FromStr;

fn main() -> io::Result<()> {
    let mut words = vec![];

    let mut s = vec![];
    let mut alnum_state = false;
    for byte in io::stdin().bytes() {
        let byte = byte?;
        let new_alnum_state = (byte as char).is_alphanumeric() || byte == b'-' || byte == b'.' || byte == b':' || byte == b'/' || byte == b'#' || byte == b'?' || byte == b'&';

        if alnum_state != new_alnum_state || !new_alnum_state {
            if let Ok(s) = String::from_utf8(s) {
                words.push(s);
            }
            s = vec![];
        }
        s.push(byte);

        alnum_state = new_alnum_state;
    }

    words.sort();
    words.dedup();

    // Try to parse words as various thingsha256
    for word in words {
        if sha256::Hash::from_str(&word).is_ok() {
            println!("hash32: {}", word);
        } else if hash160::Hash::from_str(&word).is_ok() {
            println!("hash20: {}", word);
        } else if bitcoin::Address::from_str(&word).is_ok() {
            println!("address: {}", word);
        } else if url::Url::from_str(&word).is_ok() {
            if word.len() > 7 {
                if &word[..8] == "https://" || &word[..7] == "http://" || &word[..4] == "www." {
                    println!("url: {}", word);
                }
            }
        } else if (u64::from_str(&word).is_ok() && word.len() > 4)
            || (f64::from_str(&word).is_ok() && word.len() > 4) {
            println!("num: {}", word);
        } else if let Ok(hex) = Vec::<u8>::from_hex(&word) {
            if bitcoin::Transaction::consensus_decode(&*hex).is_ok() {
                println!("tx: {}", word);
            }
        }
    }

    Ok(())
}

