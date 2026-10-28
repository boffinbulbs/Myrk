use sha3::{Digest, Sha3_512};
use thorum_hash_proof_lab::key_source::{
    Statement as KeyStatement, Witness as KeyWitness, prove_key_slots, verify_key_slots,
};
use thorum_hash_proof_lab::reconstructed_row::{
    Statement as RowStatement, Witness as RowWitness, prove_reconstructed_row,
    verify_reconstructed_row,
};
use thorum_hash_proof_lab::{Mode, Statement, Witness, prove_hash, verify_hash};

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

fn row_witness() -> RowWitness {
    let data: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../research/reconstructed-row/vectors.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let input = &data["cases"][0]["input"];
    RowWitness::from_inputs(
        bytes(input["rho_hex"].as_str().unwrap()),
        core::array::from_fn(|c| {
            core::array::from_fn(|i| input["zhat"][c][i].as_u64().unwrap() as u32)
        }),
        core::array::from_fn(|i| input["t1"][i].as_u64().unwrap() as u16),
        core::array::from_fn(|i| input["chat"][i].as_u64().unwrap() as u32),
        core::array::from_fn(|i| input["hint"][i].as_u64().unwrap() as u8),
    )
}

#[test]
#[ignore = "Serial release row API and separate profile proof corpus"]
fn conditional_row_external_api_and_separate_profiles() {
    let statement = RowStatement::new(0, [0x71; 64]).unwrap();
    let proof = prove_reconstructed_row(&row_witness(), &statement).unwrap();
    verify_reconstructed_row(&proof, &statement).unwrap();
    assert!(RowStatement::new(8, [0x71; 64]).is_err());
    let wrong_row = RowStatement::new(1, [0x71; 64]).unwrap();
    assert!(verify_reconstructed_row(&proof, &wrong_row).is_err());
    let wrong_context = RowStatement::new(0, [0x70; 64]).unwrap();
    assert!(verify_reconstructed_row(&proof, &wrong_context).is_err());

    let output = Sha3_512::digest(b"abc");
    let primitive = Statement::new(Mode::Sha3_512, 3, &output, [0x71; 64]).unwrap();
    let hash_proof = prove_hash(&Witness::from_bytes(b"abc").unwrap(), &primitive).unwrap();
    verify_hash(&hash_proof, &primitive).unwrap();
    assert!(verify_reconstructed_row(&hash_proof, &statement).is_err());
    assert!(verify_hash(&proof, &primitive).is_err());
    drop(hash_proof);

    let keys = core::array::from_fn(|slot| {
        core::array::from_fn(|i| ((i * 17 + slot * 43 + 7) % 256) as u8)
    });
    let key_statement = KeyStatement::new([0x71; 64]);
    let key_proof = prove_key_slots(&KeyWitness::from_keys(keys), &key_statement).unwrap();
    verify_key_slots(&key_proof, &key_statement).unwrap();
    assert!(verify_reconstructed_row(&key_proof, &statement).is_err());
    assert!(verify_key_slots(&proof, &key_statement).is_err());
}
