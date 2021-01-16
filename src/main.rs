
use miniscript::{self, bitcoin};
use miniscript::bitcoin::hashes::{sha256, hash160};
use miniscript::bitcoin::hashes::hex::FromHex;
use miniscript::bitcoin::consensus::Decodable;
use regex::Regex;
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
    let lines = full_string.split(&['\n'][..]);

    let hex_decoded = words
        .clone()
        .filter_map(|word| Vec::<u8>::from_hex(word).ok().map(|vec| (vec, word)));

    let alnum_words = words
        .clone()
        .filter(|word| word.chars().all(char::is_alphanumeric));

    let ips = full_string
        .split(&[' ', '\t', '\n', '/'][..])  // also split on / so that `ip a` output finds IP addresses
        .filter(|word| std::net::IpAddr::from_str(word).is_ok());

    let macs = words
        .clone()
        .filter(|word| word.chars().all(|ch| ch.is_alphabetic() || ch == ':') &&
            word.chars().filter(|ch| *ch == ':').count() == 5);

    let nums = words
        .clone()
        .filter(|word| word.len() > 3) // short numbers we don't need to copy/paste
        .filter(|word| f64::from_str(word).is_ok());

    let mut results = BTreeSet::new();

    let shell_cmd_re = Regex::new(r"^\d{2}:\d{2}\d{2}.*@.*\$ (.*)$").unwrap();
    for line in lines {
        for shell_cmd in shell_cmd_re.captures_iter(line) {
            results.insert(format!("cmd: {}", &shell_cmd[0]));
        }
    }

    for word in words {
        if url::Url::from_str(&word).is_ok() {
            if word.len() > 7 {
                if &word[..8] == "https://" || &word[..7] == "http://" || &word[..4] == "www." {
                    results.insert(format!("url: {}", word));
                }
            }
        }
    }

    for (dehex, word) in hex_decoded {
        if bitcoin::Transaction::consensus_decode(&*dehex).is_ok() {
            results.insert(format!("tx: {}", word));
        } else if bitcoin::TxOut::consensus_decode(&*dehex).is_ok() {
            results.insert(format!("txout: {}", word));
        } else if bitcoin::TxIn::consensus_decode(&*dehex).is_ok() {
            results.insert(format!("txin: {}", word));
        } else if bitcoin::BlockHeader::consensus_decode(&*dehex).is_ok() {
            results.insert(format!("header: {}", word));
        } else if bitcoin::Block::consensus_decode(&*dehex).is_ok() {
            results.insert(format!("block: {}", word));
        }
    }

    for word in alnum_words {
        if sha256::Hash::from_str(&word).is_ok() {
            results.insert(format!("hash32: {}", word));
        } else if hash160::Hash::from_str(&word).is_ok() {
            results.insert(format!("hash20: {}", word));
        } else if bitcoin::Address::from_str(&word).is_ok() {
            results.insert(format!("address: {}", word));
        } else if bitcoin::PublicKey::from_str(&word).is_ok() {
            results.insert(format!("pubkey: {}", word));
        } else if bitcoin::PrivateKey::from_str(&word).is_ok() {
            results.insert(format!("privkey: {}", word));
        } else if bitcoin::util::bip32::ExtendedPubKey::from_str(&word).is_ok() {
            results.insert(format!("xpub: {}", word));
        } else if bitcoin::util::bip32::ExtendedPrivKey::from_str(&word).is_ok() {
            results.insert(format!("xpriv: {}", word));
        } else if miniscript::Descriptor::<String>::from_str(&word).is_ok() {
            results.insert(format!("desc: {}", word));
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

