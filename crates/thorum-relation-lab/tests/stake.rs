use std::collections::BTreeSet;

use thorum_core::Amount;
use thorum_crypto_lab::AuthorizationKey;
use thorum_relation_lab::*;

const CHAIN: ChainId = [0x11; 32];
const TAG: [u8; 32] = [0x22; 32];
const DUTY: [u8; 32] = [0x33; 32];
const EPOCH: u64 = 12;

fn bond(
    owner: &AuthorizationKey,
    voter: &AuthorizationKey,
    amount: u64,
    serial: u8,
    asset: AssetId,
    epochs: (u64, u64, u64),
) -> (NoteOpening, NullifierSecret) {
    let secret = NullifierSecret::from_bytes([serial; 32]);
    let policy = BondPolicy::new(&voter.public_key(), epochs.0, epochs.1, epochs.2).unwrap();
    let opening = NoteOpening::new(
        NoteParameters {
            chain_id: CHAIN,
            creation_version: 1,
            asset_id: asset,
            amount: Amount::from_atomic(amount),
            serial: [serial; 32],
            policy: NotePolicy::Bond(policy),
        },
        &owner.public_key(),
        &secret,
        [serial.wrapping_add(1); 32],
    )
    .unwrap();
    (opening, secret)
}

fn claim(
    opening: &NoteOpening,
    secret: &NullifierSecret,
    voter: &AuthorizationKey,
    amount: u64,
) -> StakeClaim {
    StakeClaim {
        vote_nullifier: opening.vote_nullifier(secret, EPOCH, &DUTY).unwrap(),
        voting_key_binding: key_binding(&voter.public_key()).unwrap(),
        weight: Amount::from_atomic(amount),
    }
}

struct Fixture {
    owner: AuthorizationKey,
    voter: AuthorizationKey,
    statement: StakeStatement,
    witnesses: Vec<BondWitness>,
    anchor: Digest64,
    spent: BTreeSet<Digest64>,
    used: BTreeSet<Digest64>,
}

impl Fixture {
    fn with_policy(amount: u64, asset: AssetId, epochs: (u64, u64, u64)) -> Self {
        let owner = AuthorizationKey::generate().unwrap();
        let voter = AuthorizationKey::generate().unwrap();
        let (opening, secret) = bond(&owner, &voter, amount, 1, asset, epochs);
        let anchor = merkle_leaf(&CHAIN, &opening.commitment());
        let public_claim = claim(&opening, &secret, &voter, amount);
        let statement = StakeStatement {
            chain_id: CHAIN,
            protocol_version: 1,
            validation_tag: TAG,
            snapshot_anchor: anchor,
            snapshot_epoch: 10,
            epoch: EPOCH,
            duty_id: DUTY,
            decision_digest: [0x44; 64],
            required_lock_through_epoch: 13,
            claims: vec![public_claim],
        };
        let witnesses = vec![BondWitness {
            opening,
            nullifier_secret: secret,
            membership: MerklePath::new(0, vec![]).unwrap(),
            voting_public_key: voter.public_key(),
            authorization: vec![],
        }];
        let mut fixture = Self {
            owner,
            voter,
            statement,
            witnesses,
            anchor,
            spent: BTreeSet::new(),
            used: BTreeSet::new(),
        };
        fixture.resign();
        fixture
    }

    fn valid() -> Self {
        Self::with_policy(100, NATIVE_ASSET_ID, (1, 4, 20))
    }

    fn resign(&mut self) {
        let context = self.statement.authorization_context().unwrap();
        let message = self.statement.authorization_message().unwrap();
        for witness in &mut self.witnesses {
            witness.authorization = self.voter.sign(&context, &message).unwrap();
        }
    }

    fn check(&self) -> Result<Amount, RelationError> {
        check_stake_eligibility(
            &self.statement,
            &self.witnesses,
            &StakeContext {
                chain_id: CHAIN,
                protocol_version: 1,
                validation_tag: TAG,
                snapshot_anchor: self.anchor,
                snapshot_epoch: 10,
                epoch: EPOCH,
                duty_id: DUTY,
                required_lock_through_epoch: 13,
                spent_bond_nullifiers: &self.spent,
                used_vote_nullifiers: &self.used,
            },
        )
    }

    fn replace_with_two(&mut self, first: u64, second: u64) {
        let (one, one_secret) = bond(
            &self.owner,
            &self.voter,
            first,
            1,
            NATIVE_ASSET_ID,
            (1, 4, 20),
        );
        let (two, two_secret) = bond(
            &self.owner,
            &self.voter,
            second,
            2,
            NATIVE_ASSET_ID,
            (1, 4, 20),
        );
        let one_leaf = merkle_leaf(&CHAIN, &one.commitment());
        let two_leaf = merkle_leaf(&CHAIN, &two.commitment());
        self.anchor = merkle_parent(&CHAIN, &one_leaf, &two_leaf);
        self.statement.snapshot_anchor = self.anchor;
        self.statement.claims = vec![
            claim(&one, &one_secret, &self.voter, first),
            claim(&two, &two_secret, &self.voter, second),
        ];
        self.witnesses = vec![
            BondWitness {
                opening: one,
                nullifier_secret: one_secret,
                membership: MerklePath::new(0, vec![two_leaf]).unwrap(),
                voting_public_key: self.voter.public_key(),
                authorization: vec![],
            },
            BondWitness {
                opening: two,
                nullifier_secret: two_secret,
                membership: MerklePath::new(1, vec![one_leaf]).unwrap(),
                voting_public_key: self.voter.public_key(),
                authorization: vec![],
            },
        ];
        self.resign();
    }
}

#[test]
fn restricted_key_alone_authorizes_registered_snapshot_weight() {
    let fixture = Fixture::valid();
    assert_eq!(fixture.check(), Ok(Amount::from_atomic(100)));
    // The checker is passed no owner public key, owner signature or owner secret.
    assert!(fixture.spent.is_empty());
    assert!(fixture.used.is_empty());
}

#[test]
fn activation_maturity_and_exclusive_lock_boundary_are_enforced() {
    for epochs in [(11, 11, 20), (1, 11, 20)] {
        assert_eq!(
            Fixture::with_policy(100, NATIVE_ASSET_ID, epochs).check(),
            Err(RelationError::ImmatureBond)
        );
    }
    assert_eq!(
        Fixture::with_policy(100, NATIVE_ASSET_ID, (1, 4, 13)).check(),
        Err(RelationError::ExpiredBondLock)
    );
    assert_eq!(
        Fixture::with_policy(100, NATIVE_ASSET_ID, (1, 4, 14)).check(),
        Ok(Amount::from_atomic(100))
    );
}

#[test]
fn consumed_snapshot_bond_and_post_snapshot_rebond_do_not_retain_weight() {
    let mut fixture = Fixture::valid();
    fixture.spent.insert(
        fixture.witnesses[0]
            .opening
            .nullifier(&fixture.witnesses[0].nullifier_secret)
            .unwrap(),
    );
    assert_eq!(fixture.check(), Err(RelationError::AlreadySpent));
    // A new bond whose activation follows the snapshot cannot enter its eligible set.
    assert_eq!(
        Fixture::with_policy(100, NATIVE_ASSET_ID, (11, 12, 20)).check(),
        Err(RelationError::ImmatureBond)
    );
}

#[test]
fn epoch_duty_anchor_and_context_are_bound_to_external_snapshot() {
    let mut fixture = Fixture::valid();
    fixture.statement.epoch += 1;
    assert_eq!(fixture.check(), Err(RelationError::WrongEpoch));
    fixture.statement.epoch = EPOCH;
    fixture.statement.duty_id[0] ^= 1;
    assert_eq!(fixture.check(), Err(RelationError::WrongEpoch));
    fixture.statement.duty_id = DUTY;
    fixture.statement.snapshot_anchor[0] ^= 1;
    assert_eq!(fixture.check(), Err(RelationError::UntrustedAnchor));
    fixture.statement.snapshot_anchor = fixture.anchor;
    fixture.statement.validation_tag[0] ^= 1;
    assert_eq!(fixture.check(), Err(RelationError::ContextMismatch));
}

#[test]
fn decision_is_signed_but_cannot_change_the_vote_nullifier() {
    let mut fixture = Fixture::valid();
    let nullifier = fixture.statement.claims[0].vote_nullifier;
    fixture.statement.decision_digest[0] ^= 1;
    assert!(matches!(
        fixture.check(),
        Err(RelationError::Crypto(
            thorum_crypto_lab::Error::SignatureFailed
        ))
    ));
    assert_eq!(
        fixture.witnesses[0]
            .opening
            .vote_nullifier(&fixture.witnesses[0].nullifier_secret, EPOCH, &DUTY)
            .unwrap(),
        nullifier
    );
    fixture.resign();
    assert_eq!(fixture.check(), Ok(Amount::from_atomic(100)));
    fixture.used.insert(nullifier);
    assert_eq!(fixture.check(), Err(RelationError::VoteAlreadyUsed));
}

#[test]
fn wrong_restricted_key_owner_key_and_nullifier_secret_are_rejected() {
    let mut fixture = Fixture::valid();
    fixture.witnesses[0].voting_public_key = fixture.owner.public_key();
    assert_eq!(
        fixture.check(),
        Err(RelationError::RestrictedKeyNotDistinct)
    );
    fixture.witnesses[0].voting_public_key = AuthorizationKey::generate().unwrap().public_key();
    assert_eq!(fixture.check(), Err(RelationError::VotingKeyMismatch));
    fixture.witnesses[0].voting_public_key = fixture.voter.public_key();
    fixture.witnesses[0].nullifier_secret = NullifierSecret::from_bytes([0x88; 32]);
    assert_eq!(fixture.check(), Err(RelationError::NullifierSecretMismatch));
}

#[test]
fn same_bond_cannot_inflate_weight_by_a_second_claim() {
    let mut fixture = Fixture::valid();
    let (opening, secret) = bond(
        &fixture.owner,
        &fixture.voter,
        100,
        1,
        NATIVE_ASSET_ID,
        (1, 4, 20),
    );
    fixture
        .statement
        .claims
        .push(fixture.statement.claims[0].clone());
    fixture.witnesses.push(BondWitness {
        opening,
        nullifier_secret: secret,
        membership: MerklePath::new(0, vec![]).unwrap(),
        voting_public_key: fixture.voter.public_key(),
        authorization: vec![],
    });
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::DuplicateBond));
}

#[test]
fn stake_weight_is_linear_under_partition_and_uses_checked_totals() {
    let single = Fixture::valid();
    let mut split = Fixture::valid();
    split.replace_with_two(40, 60);
    assert_eq!(single.check().unwrap(), split.check().unwrap());
    assert_eq!(split.check(), Ok(Amount::from_atomic(100)));
    split.replace_with_two(u64::MAX, 1);
    assert_eq!(split.check(), Err(RelationError::AmountOverflow));
}

#[test]
fn zero_non_native_and_forged_weights_are_rejected() {
    assert_eq!(
        Fixture::with_policy(0, NATIVE_ASSET_ID, (1, 4, 20)).check(),
        Err(RelationError::NonNativeBond)
    );
    assert_eq!(
        Fixture::with_policy(100, [4; 32], (1, 4, 20)).check(),
        Err(RelationError::NonNativeBond)
    );
    let mut fixture = Fixture::valid();
    fixture.statement.claims[0].weight = Amount::from_atomic(101);
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::WeightMismatch));
}

#[test]
fn invalid_policy_order_and_shared_owner_vote_key_are_rejected() {
    let key = AuthorizationKey::generate().unwrap();
    assert!(matches!(
        BondPolicy::new(&key.public_key(), 3, 2, 20),
        Err(RelationError::InvalidBondPolicy)
    ));
    let policy = BondPolicy::new(&key.public_key(), 1, 2, 20).unwrap();
    let secret = NullifierSecret::from_bytes([1; 32]);
    assert!(matches!(
        NoteOpening::new(
            NoteParameters {
                chain_id: CHAIN,
                creation_version: 1,
                asset_id: NATIVE_ASSET_ID,
                amount: Amount::from_atomic(100),
                serial: [1; 32],
                policy: NotePolicy::Bond(policy)
            },
            &key.public_key(),
            &secret,
            [2; 32],
        ),
        Err(RelationError::RestrictedKeyNotDistinct)
    ));
}
