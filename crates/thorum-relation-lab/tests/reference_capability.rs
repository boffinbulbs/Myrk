//! V2 recipient bytes and digests checked against a separate Python implementation.

use thorum_core::Amount;
use thorum_relation_lab::{
    merkle_leaf, BondPolicy, MerklePath, NoteOpening, NoteParameters, NotePolicy, NullifierSecret,
    RecipientCapability, RecoveryContext,
};

const VECTORS: &str = include_str!("../../../research/relations/recipient_vectors.csv");

fn bytes(name: &str) -> Vec<u8> {
    let text = VECTORS
        .lines()
        .skip(1)
        .find_map(|line| line.split_once(',').filter(|(key, _)| *key == name))
        .unwrap_or_else(|| panic!("missing recipient reference field {name}"))
        .1;
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
fn recipient_capability_and_note_digests_match_independent_v2_vectors() {
    let chain = fixed("chain");
    let owner = bytes("owner_public_key");
    let voter = bytes("voting_public_key");
    let kem_key = bytes("recipient_public_key");
    let secret = NullifierSecret::from_bytes(fixed("nullifier_secret"));
    let capability = RecipientCapability::new(chain, &owner, &kem_key, &secret).unwrap();
    assert_eq!(capability.to_bytes(), bytes("capability"));
    assert_eq!(capability.owner_key_binding(), fixed("owner_key_binding"));
    assert_eq!(
        capability.nullifier_secret_binding(),
        fixed("nullifier_secret_binding")
    );
    assert_eq!(
        capability.encryption_key_binding(),
        fixed("recipient_key_binding")
    );
    let decoded = RecipientCapability::from_bytes(&bytes("capability"), chain).unwrap();
    assert!(decoded == capability);
    for (name, asset, amount, policy) in [
        ("payment", [0xA7; 32], 123456789012345, NotePolicy::Payment),
        (
            "bond",
            [0; 32],
            987654321,
            NotePolicy::Bond(BondPolicy::new(&voter, 5, 7, 20).unwrap()),
        ),
    ] {
        let opening = NoteOpening::new_recipient(
            NoteParameters {
                chain_id: chain,
                creation_version: 1,
                asset_id: asset,
                amount: Amount::from_atomic(amount),
                serial: fixed("serial"),
                policy,
            },
            &decoded,
            fixed("blinding"),
        )
        .unwrap();
        assert_eq!(
            opening.private_opening_bytes().as_slice(),
            bytes(&format!("{name}_opening"))
        );
        assert_eq!(opening.commitment(), fixed(&format!("{name}_commitment")));
        let restored = NoteOpening::recover_recipient(
            &bytes(&format!("{name}_opening")),
            &RecoveryContext {
                chain_id: chain,
                creation_version: 1,
                expected_commitment: fixed(&format!("{name}_commitment")),
            },
            &decoded,
            &secret,
        )
        .unwrap();
        assert_eq!(restored.encoding_version(), 2);
        assert_eq!(restored.commitment(), opening.commitment());
        assert_eq!(
            opening.nullifier(&secret).unwrap(),
            fixed(&format!("{name}_nullifier"))
        );
        assert_eq!(
            restored.nullifier(&secret).unwrap(),
            opening.nullifier(&secret).unwrap()
        );
        assert_eq!(
            opening.vote_nullifier(&secret, 9, &[0x39; 32]).unwrap(),
            fixed(&format!("{name}_vote_nullifier"))
        );
        assert_eq!(
            merkle_leaf(&chain, &opening.commitment()),
            fixed(&format!("{name}_merkle_leaf"))
        );
        let path = MerklePath::new(5, vec![[0x10; 64], [0x20; 64], [0x30; 64]]).unwrap();
        assert_eq!(
            path.root(&chain, &opening.commitment()),
            fixed(&format!("{name}_merkle_root_index_5"))
        );
    }
}
