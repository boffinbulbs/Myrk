use sha3::{Digest, Sha3_512};
use thorum_hash_proof_lab::key_source::{
    Statement as KeyStatement, Witness as KeyWitness, prove_key_slots, verify_key_slots,
};
use thorum_hash_proof_lab::{Mode, Statement, Witness, prove_hash, verify_hash};

#[test]
fn private_key_source_api_verifies_and_other_profiles_reject() {
    let keys = core::array::from_fn(|slot| {
        core::array::from_fn(|i| ((i * 17 + slot * 43 + 7) % 256) as u8)
    });
    let statement = KeyStatement::new([0x71; 64]);
    let proof = prove_key_slots(&KeyWitness::from_keys(keys), &statement).unwrap();
    verify_key_slots(&proof, &statement).unwrap();

    let output = Sha3_512::digest(b"abc");
    let primitive = Statement::new(Mode::Sha3_512, 3, &output, [0x71; 64]).unwrap();
    let hash_proof = prove_hash(&Witness::from_bytes(b"abc").unwrap(), &primitive).unwrap();
    verify_hash(&hash_proof, &primitive).unwrap();
    assert!(verify_key_slots(&hash_proof, &statement).is_err());
    assert!(verify_hash(&proof, &primitive).is_err());
}
