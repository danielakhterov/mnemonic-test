mod wordlist;

fn main() {
    #[rustfmt::skip]
    let words = [
        "obvious",
        "favorite",
        "remain",
        "caution",
        "remove",
        "laptop",
        "base",
        "vacant",
        "increase",
        "video",
        "erase",
        "pass",
        "sniff",
        "sausage",
        "knock",
        "grid",
        "argue",
        "salt",
        "romance",
        "way",
        "alone",
        "fever",
        "slush",
        "dune",
    ];

    // Public  => 0e19f99800b007cc7c82f9d85b73e0f6e48799469450caf43f253b48c4d0d91a
    // Private => 2b7345f302a10c2a6d55bf8b7af40f125ec41d780957826006d30776f0c441fb

    for i in -100..100 {
        println!("{}", hex::encode(&key_at_index(hgc_seed(&words), i)));
    }
}

fn key_at_index(entropy: Vec<u8>, index: i64) -> Vec<u8> {
    derive_key(&entropy, index)
}

// https://github.com/hashgraph/hedera-wallet-android/blob/b717484a0b37291b6975369830344f8855aaae51/app/src/main/java/hedera/hgc/hgcwallet/crypto/HGCSeed.java#L38
fn hgc_seed(words: &[&'static str]) -> Vec<u8> {
    to_entropy(words)
}

// https://github.com/hashgraph/hedera-wallet-android/blob/master/app/src/main/java/hedera/hgc/hgcwallet/crypto/CryptoUtils.java#L68
fn derive_key(seed: &[u8], index: i64) -> Vec<u8> {
    let mut password = vec![0u8; seed.len() + 8];

    password[..seed.len()].copy_from_slice(&seed);
    password[seed.len()..].copy_from_slice(&index.to_le_bytes());

    let salt = [0xFFu8; 1];

    let mut derived_key = vec![0u8; 32];

    let digest = crypto::sha2::Sha512::new();
    let mut hmac = crypto::hmac::Hmac::new(digest, &password);
    crypto::pbkdf2::pbkdf2(&mut hmac, &salt[..], 2048, &mut derived_key);

    derived_key
}

// https://github.com/hashgraph/hedera-wallet-android/blob/master/app/src/main/java/hedera/hgc/hgcwallet/crypto/bip39/Mnemonic.java#L57
fn to_entropy(words: &[&'static str]) -> Vec<u8> {
    let concat_bits_len = words.len() * 11;
    let mut concat_bits = vec![false; concat_bits_len];

    for (word_index, word) in words.iter().enumerate() {
        let index = wordlist::WORDLIST.binary_search(&word).unwrap();

        for i in 0..11 {
            concat_bits[(word_index * 11) + i] = (index & (1 << (10 - i))) != 0;
        }
    }

    let checksum_bits_len = concat_bits_len / 33;
    let entropy_bits_len = concat_bits_len - checksum_bits_len;

    let mut entropy = vec![entropy_bits_len / 8];
    for (i, entropy) in entropy.iter_mut().enumerate() {
        for j in 0..8 {
            if concat_bits[(i * 8) + j] {
                *entropy |= 1 << (7 - j);
            }
        }
    }

    entropy.into_iter().map(|i| i as u8).collect()
}
