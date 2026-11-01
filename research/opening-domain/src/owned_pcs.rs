//! Private typed calls to the three actual composite commitment entries.
#![forbid(unsafe_code)]
use crate::{
    HidingFriPcs, HidingFriProverError,
    composite::{Challenge, CompositeStore, Error, QuotientInput, RawInput},
    hiding_pcs::MainQuotientView,
};
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::{Mmcs, Pcs, UnivariateStarkPcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
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
        ProverError = crate::domain::OpeningProverError<HidingFriProverError>,
    > + Sized
{
    fn commit_main_owned(
        &self,
        domain: Self::Domain,
        raw: RawInput,
    ) -> Result<(Self::Commitment, Self::ProverData), Error>;
    fn main_quotient_view_owned<'a>(
        &self,
        data: &'a Self::ProverData,
        domain: Self::Domain,
    ) -> Result<MainQuotientView<'a>, Error>;
    fn commit_quotient_owned(
        &self,
        domain: Self::Domain,
        source: QuotientInput,
    ) -> Result<(Self::Commitment, Self::ProverData), Error>;
    fn commit_auxiliary_owned(
        &self,
        domain: Self::Domain,
    ) -> Result<Option<CommitmentPair<Self, C>>, Error>;
}
impl<D, I, F, R, C> OwnedPcs<C>
    for crate::domain::OpeningChecked<HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>>
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
        self.retained().commit_composite_main(domain, raw)
    }
    fn main_quotient_view_owned<'a>(
        &self,
        data: &'a Self::ProverData,
        domain: Self::Domain,
    ) -> Result<MainQuotientView<'a>, Error> {
        self.retained().main_quotient_view(data, domain)
    }
    fn commit_quotient_owned(
        &self,
        domain: Self::Domain,
        source: QuotientInput,
    ) -> Result<(Self::Commitment, Self::ProverData), Error> {
        self.retained().commit_quotient_source(domain, source)
    }
    fn commit_auxiliary_owned(
        &self,
        domain: Self::Domain,
    ) -> Result<Option<(Self::Commitment, Self::ProverData)>, Error> {
        self.retained()
            .commit_composite_auxiliary::<C>(domain)
            .map(Some)
    }
}
