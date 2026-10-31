//! Fixed relation context. No public configuration, raw handle or success mutator.
#![forbid(unsafe_code)]
use crate::{
    HidingFriPcs, HidingFriProverError,
    composite::{Challenge, CompositeStore, Error, Snapshot},
};
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_uni_stark::{Proof, ProvingError, StarkConfig, StarkGenericConfig};
use rand::{CryptoRng, SeedableRng};

pub type OwnedConfig<D, I, F, R, C> =
    StarkConfig<HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>, Challenge, C>;
pub type OwnedProof<D, I, F, R, C> = Proof<OwnedConfig<D, I, F, R, C>>;
pub type ProvingResult<D, I, F, R, C> = Result<OwnedProof<D, I, F, R, C>, OwnedError>;

#[derive(Debug)]
pub enum OwnedError {
    ReleaseRequired,
    Context,
    Storage { phase: &'static str, source: Error },
    Backend(ProvingError<HidingFriProverError>),
}
impl From<Error> for OwnedError {
    fn from(source: Error) -> Self {
        Self::Storage {
            phase: "owned lifecycle",
            source,
        }
    }
}
impl From<ProvingError<HidingFriProverError>> for OwnedError {
    fn from(error: ProvingError<HidingFriProverError>) -> Self {
        Self::Backend(error)
    }
}

/// A context owns one finite attempt. It cannot be cloned or reset.
pub struct Context<D, I, F, R, C> {
    config: OwnedConfig<D, I, F, R, C>,
    store: CompositeStore,
}
impl<D, I, F, R, C> Context<D, I, F, R, C>
where
    D: TwoAdicSubgroupDft<BabyBear> + Clone,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync> + Clone,
    F: Mmcs<Challenge> + Clone,
    R: CryptoRng + SeedableRng + Send + Sync,
    C: FieldChallenger<BabyBear>
        + GrindingChallenger<Witness = BabyBear>
        + CanObserve<I::Commitment>
        + CanObserve<F::Commitment>
        + CanSample<Challenge>
        + Clone,
{
    /// The actual target profile is checked before any raw input is written.
    /// The anchor supplies only the existing checked resource constructor.
    pub fn new<D0, I0, F0, R0, S0>(
        pcs: HidingFriPcs<BabyBear, D, I, F, R>,
        challenger: C,
        anchor: &kova_proof_preflight::HidingFriPcs<BabyBear, D0, I0, F0, R0, S0>,
    ) -> Result<Self, OwnedError>
    where
        D0: TwoAdicSubgroupDft<BabyBear>,
        I0: Mmcs<BabyBear>,
        F0: Mmcs<Challenge>,
        R0: CryptoRng + Send + Sync,
        S0: kova_proof_preflight::storage::MatrixStore<BabyBear>,
    {
        if cfg!(debug_assertions) {
            return Err(OwnedError::ReleaseRequired);
        }
        pcs.composite_profile()?;
        let store = CompositeStore::new(anchor)?;
        // This constructor moves the PCS. Only initialise_challenger clones
        // its original public transcript state. No PCS/config clone occurs.
        let config = StarkConfig::new(pcs.with_storage(store.clone()), challenger);
        if config.ood_proof_of_work_bits() != 0
            || config.lookup_proof_of_work_bits() != 0
            || config.is_zk() != 1
        {
            return Err(OwnedError::Context);
        }
        Ok(Self { config, store })
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        self.store.snapshot()
    }
    /// Ownership and canonical shape checks do not precheck the AIR witness.
    pub fn prove(
        &self,
        values: impl IntoIterator<Item = BabyBear>,
    ) -> ProvingResult<D, I, F, R, C> {
        if cfg!(debug_assertions) {
            return Err(OwnedError::ReleaseRequired);
        }
        self.config.pcs().composite_profile()?;
        if self.config.ood_proof_of_work_bits() != 0
            || self.config.lookup_proof_of_work_bits() != 0
            || self.config.is_zk() != 1
        {
            return Err(OwnedError::Context);
        }
        #[cfg(not(debug_assertions))]
        {
            let raw = self.store.write_raw(values)?;
            crate::owned_prover::prove_owned(&self.config, &self.store, raw)
        }
        #[cfg(debug_assertions)]
        {
            let _ = values;
            Err(OwnedError::ReleaseRequired)
        }
    }
    /// Main-only diagnostic prefix. Its actual failure closes the original
    /// attempt and is never returned as a proof or resumable transcript.
    pub(crate) fn opening_prefix(
        &self,
        values: impl IntoIterator<Item = BabyBear>,
        selected: crate::hiding_pcs::OpeningCase,
    ) -> Result<crate::hiding_pcs::OpeningObservation, OwnedError>
    where
        I::ProverData<crate::composite::Stored>: Clone,
    {
        use crate::composite::Step;
        use p3_commit::Pcs;
        if cfg!(debug_assertions) {
            return Err(OwnedError::ReleaseRequired);
        }
        self.config.pcs().composite_profile()?;
        if self.config.ood_proof_of_work_bits() != 0
            || self.config.lookup_proof_of_work_bits() != 0
            || self.config.is_zk() != 1
        {
            return Err(OwnedError::Context);
        }
        let raw = self.store.write_raw(values)?;
        let attempt = self.store.begin_attempt(&raw)?;
        let mut step = Step::new(&self.store);
        let result: Result<_, OwnedError> = (|| {
            let pcs = self.config.pcs();
            let domain = <HidingFriPcs<BabyBear, D, I, F, R, CompositeStore> as Pcs<
                Challenge,
                C,
            >>::natural_domain_for_degree(pcs, 512);
            let (_, data) = pcs.commit_composite_main(domain, raw)?;
            let mut challenger = self.config.initialise_challenger();
            Ok(pcs.private_opening_control(&data, &mut challenger, selected))
        })();
        match &result {
            Ok(observation) => step.fail(observation.cause.clone()),
            Err(error) => {
                let cause = match error {
                    OwnedError::Storage { source, .. } => source.clone(),
                    OwnedError::Backend(ProvingError::Pcs { source, .. }) => Error::Mask(*source),
                    _ => Error::Incomplete,
                };
                step.fail(cause);
            }
        }
        drop(attempt);
        result
    }
}
