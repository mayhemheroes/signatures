#![no_main]
use libfuzzer_sys::fuzz_target;
use dsa::{Components, BigUint, VerifyingKey, SigningKey};

fuzz_target!(|value: (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>)| {
    let (p, q, g, pubkey, privkey) = value;
    match Components::from_components(BigUint::new(p), BigUint::new(q), BigUint::new(g)) {
        Ok(components) => {
            if let Ok(verifying_key) = VerifyingKey::from_components(
                components, BigUint::new(pubkey)
            ) {
                let _ = SigningKey::from_components(verifying_key, BigUint::new(privkey));
            };
        },
        Err(_) => {}
    }
});