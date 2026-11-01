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

pub type OwnedConfig<D, I, F, R, C> = StarkConfig<
    crate::domain::OpeningChecked<HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>>,
    Challenge,
    C,
>;
pub type OwnedProof<D, I, F, R, C> = Proof<OwnedConfig<D, I, F, R, C>>;
pub type ProvingResult<D, I, F, R, C> = Result<OwnedProof<D, I, F, R, C>, OwnedError>;

#[derive(Debug)]
pub enum OwnedError {
    ReleaseRequired,
    Context,
    Storage { phase: &'static str, source: Error },
    Backend(ProvingError<crate::domain::OpeningProverError<HidingFriProverError>>),
}
impl From<Error> for OwnedError {
    fn from(source: Error) -> Self {
        Self::Storage {
            phase: "owned lifecycle",
            source,
        }
    }
}
impl From<ProvingError<crate::domain::OpeningProverError<HidingFriProverError>>> for OwnedError {
    fn from(error: ProvingError<crate::domain::OpeningProverError<HidingFriProverError>>) -> Self {
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
        let config = StarkConfig::new(
            crate::domain::OpeningChecked::new(pcs.with_storage(store.clone())),
            challenger,
        );
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
        self.prove_with(|| self.store.write_raw(values))
    }
    /// Fallible raw data follows the actual owned proving lifecycle. Storage
    /// failure returns before any main commitment or transcript initialization.
    pub fn try_prove(
        &self,
        values: impl IntoIterator<Item = Result<BabyBear, kova_fallible_input::Error>>,
    ) -> ProvingResult<D, I, F, R, C> {
        self.prove_with(|| self.store.try_write_raw(values))
    }
    fn prove_with(
        &self,
        write: impl FnOnce() -> Result<crate::composite::RawInput, Error>,
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
            let raw = write()?;
            crate::owned_prover::prove_owned(&self.config, &self.store, raw)
        }
        #[cfg(debug_assertions)]
        {
            let _ = write;
            Err(OwnedError::ReleaseRequired)
        }
    }

    /// Terminal direct guard control. It does not sample an OOD challenge.
    pub(crate) fn trace_domain_refusal(
        &self,
        values: impl IntoIterator<Item = Result<BabyBear, kova_fallible_input::Error>>,
        audit: &crate::diagnostics_setup::Audit,
    ) -> Result<crate::diagnostics::TraceObservation, OwnedError> {
        use crate::owned_pcs::OwnedPcs;
        use p3_commit::Pcs;
        use p3_field::PrimeCharacteristicRing;
        let raw = self.store.try_write_raw(values)?;
        let attempt = self.store.begin_attempt(&raw)?;
        let mut step = crate::composite::Step::new(&self.store);
        let result: Result<_, OwnedError> = (|| {
            let pcs = self.config.pcs();
            let extended = <_ as Pcs<Challenge, C>>::natural_domain_for_degree(pcs, 512);
            let (_, data) = <_ as OwnedPcs<C>>::commit_main_owned(pcs, extended, raw)?;
            let raw_domain = <_ as Pcs<Challenge, C>>::natural_domain_for_degree(pcs, 256);
            let lease = pcs.domain_lease(&data)?;
            let flag_before = pcs.domain_opened(&data);
            let before_guard = audit.detailed_counts();
            // Explicit public control point, not a claimed natural sample.
            let cause = match crate::trace_admission::admit_raw(raw_domain, Challenge::ONE) {
                Err(cause) => cause,
                Ok(()) => panic!("raw trace point must refuse before opening"),
            };
            let after_guard = audit.detailed_counts();
            let flag_after = pcs.domain_opened(&data);
            self.store.check_phase(crate::Phase::MainCommitted)?;
            drop(data);
            Ok(crate::diagnostics::TraceObservation {
                cause,
                lease,
                flag_before,
                flag_after,
                before_guard,
                after_guard,
            })
        })();
        match &result {
            Ok(observation) => step.fail(Error::OpeningDomain(observation.cause)),
            Err(OwnedError::Storage { source, .. }) => step.fail(source.clone()),
            Err(_) => step.fail(Error::Incomplete),
        }
        drop(attempt);
        result
    }
}
