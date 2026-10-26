use thorum_arithmetic_proof_lab::{
    Error, Statement, Witness, mul::MODULUS, prove_mod_mul, verify_mod_mul,
};

#[test]
fn public_primitive_interface_proves_extremes_and_rejects_field_aliases() {
    for (x, y) in [
        (0, 0),
        (MODULUS - 1, MODULUS - 1),
        (20479, 6705151),
        (MODULUS - 1, 4095),
    ] {
        let z = (u64::from(x) * u64::from(y) % u64::from(MODULUS)) as u32;
        let statement = Statement::new(x, y, z, [0x51; 64]).unwrap();
        let witness = Witness::for_operands(x, y).unwrap();
        let proof = prove_mod_mul(&witness, &statement).unwrap();
        verify_mod_mul(&proof, &statement).unwrap();
        let changed = Statement::new(x, y, (z + 1) % MODULUS, [0x51; 64]).unwrap();
        assert_eq!(verify_mod_mul(&proof, &changed), Err(Error::InvalidProof));
        let changed_context = Statement::new(x, y, z, [0x52; 64]).unwrap();
        assert_eq!(
            verify_mod_mul(&proof, &changed_context),
            Err(Error::InvalidProof)
        );
    }
    let false_integer = Statement::new(8_380_416, 8_380_416, 6_414_577, [0; 64]).unwrap();
    let honest = Witness::for_operands(8_380_416, 8_380_416).unwrap();
    assert_eq!(
        prove_mod_mul(&honest, &false_integer),
        Err(Error::InvalidWitness)
    );
    assert!(matches!(
        Statement::new(2_013_265_921, 0, 0, [0; 64]),
        Err(Error::InvalidStatement)
    ));
}
