
use bitcoin;
use bitcoin::hashes::{sha256, hash160};
use bitcoin::hashes::hex::FromHex;
use bitcoin::consensus::Decodable;
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::str::FromStr;

fn main() -> io::Result<()> {
    // Capture screen
    let full_string = {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        s
    };

    // Split in various ways
    let words = full_string.split(&[' ', '\t', '\n'][..]);

    let alnum_words = words
        .clone()
        .filter(|word| word.chars().all(char::is_alphanumeric));

    let ips = words
        .clone()
        .filter(|word| std::net::IpAddr::from_str(word).is_ok());

    let macs = words
        .clone()
        .filter(|word| word.chars().all(|ch| ch.is_alphabetic() || ch == ':') &&
            word.chars().filter(|ch| *ch == ':').count() == 5);

    let nums = words
        .clone()
        .filter(|word| f64::from_str(word).is_ok());

    let mut results = BTreeSet::new();
    for word in words {
        if url::Url::from_str(&word).is_ok() {
            if word.len() > 7 {
                if &word[..8] == "https://" || &word[..7] == "http://" || &word[..4] == "www." {
                    results.insert(format!("url: {}", word));
                }
            }
        }
    }

    for word in alnum_words {
        if sha256::Hash::from_str(&word).is_ok() {
            results.insert(format!("hash32: {}", word));
        } else if hash160::Hash::from_str(&word).is_ok() {
            results.insert(format!("hash20: {}", word));
        } else if bitcoin::Address::from_str(&word).is_ok() {
            results.insert(format!("address: {}", word));
        }
    }

    for word in ips {
        results.insert(format!("ip: {}", word));
    }

    for word in macs {
        results.insert(format!("mac: {}", word));
    }

    for word in nums {
        results.insert(format!("num: {}", word));
    }

    // Output
    for line in results {
        println!("{}", line);
    }

    Ok(())
}

