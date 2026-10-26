use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationError {
    InvalidEncoding,
    UnsupportedEncoding,
    CapabilityMismatch,
    RecipientKeyMismatch,
    LimitExceeded,
    InvalidPath,
    ChainMismatch,
    VersionMismatch,
    ContextMismatch,
    UntrustedAnchor,
    MembershipFailed,
    NullifierSecretMismatch,
    NullifierMismatch,
    DuplicateNullifier,
    AlreadySpent,
    CommitmentMismatch,
    OwnerKeyMismatch,
    ConservationFailed,
    AmountOverflow,
    BondSpendUnsupported,
    InvalidBondPolicy,
    RestrictedKeyNotDistinct,
    NotBond,
    NonNativeBond,
    ImmatureBond,
    ExpiredBondLock,
    InvalidSnapshot,
    WrongEpoch,
    VotingKeyMismatch,
    DuplicateBond,
    VoteNullifierMismatch,
    VoteAlreadyUsed,
    WeightMismatch,
    Crypto(thorum_crypto_lab::Error),
}

impl From<thorum_crypto_lab::Error> for RelationError {
    fn from(error: thorum_crypto_lab::Error) -> Self {
        Self::Crypto(error)
    }
}

impl fmt::Display for RelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEncoding => "invalid canonical recipient encoding",
            Self::UnsupportedEncoding => "unsupported recipient codec or policy",
            Self::CapabilityMismatch => "opening does not match the recipient capability",
            Self::RecipientKeyMismatch => "delivery key does not match the committed recipient key",
            Self::LimitExceeded => "local relation input limit exceeded",
            Self::InvalidPath => "invalid bounded Merkle path",
            Self::ChainMismatch => "chain identifier mismatch",
            Self::VersionMismatch => "note or relation version mismatch",
            Self::ContextMismatch => "external validation context mismatch",
            Self::UntrustedAnchor => "anchor is not allowed by the external context",
            Self::MembershipFailed => "opening does not have the claimed Merkle membership",
            Self::NullifierSecretMismatch => "nullifier secret does not open its committed binding",
            Self::NullifierMismatch => "input nullifier does not match the opening",
            Self::DuplicateNullifier => "duplicate input nullifier",
            Self::AlreadySpent => "input is present in the external spent set",
            Self::CommitmentMismatch => "output commitment does not match its opening",
            Self::OwnerKeyMismatch => "authorization key does not match the committed owner",
            Self::ConservationFailed => "ordinary payment does not conserve each asset",
            Self::AmountOverflow => "asset or weight total exceeds the atomic amount range",
            Self::BondSpendUnsupported => "bond exit is outside the payment checker",
            Self::InvalidBondPolicy => "invalid committed bond epoch ordering",
            Self::RestrictedKeyNotDistinct => "voting and spending keys must be distinct",
            Self::NotBond => "stake witness is not a committed bond note",
            Self::NonNativeBond => "stake weight requires positive native value",
            Self::ImmatureBond => "bond is not activated and mature at the snapshot",
            Self::ExpiredBondLock => "bond does not remain locked through the required epoch",
            Self::InvalidSnapshot => "invalid external snapshot epoch or lock parameters",
            Self::WrongEpoch => "stake statement does not match the external epoch or duty",
            Self::VotingKeyMismatch => "voting key does not match the immutable bond policy",
            Self::DuplicateBond => "the same bond contributes weight more than once",
            Self::VoteNullifierMismatch => "vote nullifier does not match the bond and duty",
            Self::VoteAlreadyUsed => "vote nullifier is present in the external used set",
            Self::WeightMismatch => "claimed weight differs from the committed bond amount",
            Self::Crypto(error) => return error.fmt(f),
        };
        f.write_str(message)
    }
}

impl std::error::Error for RelationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}
