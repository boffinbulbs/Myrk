//! Private typed calls to the three actual composite commitment entries.
#![forbid(unsafe_code)]
use crate::{
    HidingFriPcs, HidingFriProverError,
    composite::{Challenge, CompositeStore, Error, RawInput},
};
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{Mmcs, Pcs, UnivariateStarkPcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_matrix::dense::RowMajorMatrix;
use rand::CryptoRng;

type CommitmentPair<P, C> = (
    <P as Pcs<Challenge, C>>::Commitment,
    <P as Pcs<Challenge, C>>::ProverData,
);
pub(crate) trait OwnedPcs<C>:
    UnivariateStarkPcs<
        Challenge,
        C,
        Domain = TwoAdicMultiplicativeCoset<BabyBear>,
        ProverError = HidingFriProverError,
    > + Sized
{
    fn commit_main_owned(
        &self,
        domain: Self::Domain,
        raw: RawInput,
    ) -> Result<(Self::Commitment, Self::ProverData), Error>;
    fn commit_quotient_owned(
        &self,
        domain: Self::Domain,
        values: RowMajorMatrix<BabyBear>,
        chunks: usize,
    ) -> Result<(Self::Commitment, Self::ProverData), Error>;
    fn commit_auxiliary_owned(
        &self,
        domain: Self::Domain,
    ) -> Result<Option<CommitmentPair<Self, C>>, Error>;
}
impl<D, I, F, R, C> OwnedPcs<C> for HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<Challenge>,
    R: CryptoRng + Send + Sync,
    C: FieldChallenger<BabyBear>
        + GrindingChallenger<Witness = BabyBear>
        + CanObserve<I::Commitment>
        + CanObserve<F::Commitment>,
{
    fn commit_main_owned(
        &self,
        domain: Self::Domain,
        raw: RawInput,
    ) -> Result<(Self::Commitment, Self::ProverData), Error> {
        self.commit_composite_main(domain, raw)
    }
    fn commit_quotient_owned(
        &self,
        domain: Self::Domain,
        values: RowMajorMatrix<BabyBear>,
        chunks: usize,
    ) -> Result<(Self::Commitment, Self::ProverData), Error> {
        self.commit_composite_quotient::<C>(domain, values, chunks)
    }
    fn commit_auxiliary_owned(
        &self,
        domain: Self::Domain,
    ) -> Result<Option<(Self::Commitment, Self::ProverData)>, Error> {
        self.commit_composite_auxiliary::<C>(domain).map(Some)
    }
}
