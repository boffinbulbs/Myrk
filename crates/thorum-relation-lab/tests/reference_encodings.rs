//! Exact relation bytes checked against the independent Python reference.

use thorum_core::Amount;
use thorum_relation_lab::{
    key_binding, merkle_leaf, BondPolicy, MerklePath, NoteOpening, NoteParameters, NotePolicy,
    NullifierSecret,
};

const VECTORS: &str = include_str!("../../../research/relations/reference_vectors.csv");

fn field(name: &str) -> &'static str {
    VECTORS
        .lines()
        .skip(1)
        .find_map(|line| line.split_once(',').filter(|(key, _)| *key == name))
        .unwrap_or_else(|| panic!("missing reference field {name}"))
        .1
}

fn bytes(name: &str) -> Vec<u8> {
    let text = field(name);
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn fixed<const N: usize>(name: &str) -> [u8; N] {
    bytes(name).try_into().unwrap()
}

#[test]
fn complete_openings_and_full_digests_match_independent_vectors() {
    let owner = bytes("owner_public_key");
    let voter = bytes("voting_public_key");
    let secret = NullifierSecret::from_bytes(fixed("nullifier_secret"));
    let chain = fixed("chain");
    assert_eq!(key_binding(&owner).unwrap(), fixed("owner_key_binding"));
    assert_eq!(key_binding(&voter).unwrap(), fixed("voting_key_binding"));
    for (name, asset, amount, policy) in [
        ("payment", [0xA7; 32], 123456789012345, NotePolicy::Payment),
        (
            "bond",
            [0; 32],
            987654321,
            NotePolicy::Bond(BondPolicy::new(&voter, 5, 7, 20).unwrap()),
        ),
    ] {
        let note = NoteOpening::new(
            NoteParameters {
                chain_id: chain,
                creation_version: 1,
                asset_id: asset,
                amount: Amount::from_atomic(amount),
                serial: fixed("serial"),
                policy,
            },
            &owner,
            &secret,
            fixed("blinding"),
        )
        .unwrap();
        assert_eq!(
            note.private_opening_bytes().as_slice(),
            bytes(&format!("{name}_opening"))
        );
        assert_eq!(note.commitment(), fixed(&format!("{name}_commitment")));
        assert_eq!(
            note.nullifier(&secret).unwrap(),
            fixed(&format!("{name}_nullifier"))
        );
        assert_eq!(
            note.vote_nullifier(&secret, 9, &[0x39; 32]).unwrap(),
            fixed(&format!("{name}_vote_nullifier"))
        );
        assert_eq!(
            merkle_leaf(&chain, &note.commitment()),
            fixed(&format!("{name}_merkle_leaf"))
        );
        let path = MerklePath::new(5, vec![[0x10; 64], [0x20; 64], [0x30; 64]]).unwrap();
        assert_eq!(
            path.root(&chain, &note.commitment()),
            fixed(&format!("{name}_merkle_root_index_5"))
        );
    }
}
