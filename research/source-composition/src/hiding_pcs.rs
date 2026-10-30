#![forbid(unsafe_code)]
#![allow(clippy::nonminimal_bool)]
include!("../../storage-pcs/backend/src/hiding_pcs.rs");

use crate::composite::{
    Challenge as E4, CompositeStore, Error as CompositeError, Phase, RawInput, Step, Stored,
};
use p3_baby_bear::BabyBear;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};

pub type CompositeCommitment<I> = (
    <I as Mmcs<BabyBear>>::Commitment,
    HidingFriPcsProverData<<I as Mmcs<BabyBear>>::ProverData<Stored>>,
);

impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
    fn composite_profile(&self) -> Result<(), CompositeError> {
        let f = &self.inner.fri;
        if self.num_random_codewords != 4
            || f.num_queries != 64
            || f.log_blowup != 3
            || f.log_final_poly_len != 0
            || f.max_log_arity != 1
            || [
                f.batch_proof_of_work_bits,
                f.commit_proof_of_work_bits,
                f.query_proof_of_work_bits,
            ] != [0; 3]
        {
            return Err(CompositeError::Shape);
        }
        self.check_hiding_budget(256, <E4 as BasedVectorSpace<BabyBear>>::DIMENSION, 2)
            .map_err(CompositeError::Mask)
    }
    /// Wrap the concrete main LDE before the actual retained MMCS operation.
    pub fn commit_composite_main(
        &self,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
        raw: RawInput,
    ) -> Result<CompositeCommitment<I>, CompositeError> {
        self.composite_profile()?;
        if domain.size() != 512 || domain.shift() != BabyBear::ONE {
            return Err(CompositeError::Domain);
        }
        let store = &self.inner.storage;
        store.check_raw(&raw)?;
        store.transition(Phase::MainReady, Phase::MainPreparing)?;
        let mut step = Step::new(store);
        let result: Result<_, CompositeError> = (|| {
            let mut main_attempt = store.main().begin(false)?;
            let prepared = {
                let mut rng = self.rng.lock();
                store.main().prepare_owned(raw.inner, &mut *rng)?
            };
            let lde = store.main().extend(prepared, &self.inner.dft)?;
            store.main().committing()?;
            store.transition(Phase::MainPreparing, Phase::MainCommitting)?;
            let lde = store.wrap_main(lde);
            let (root, data) = self.inner.commit_stored_ldes(alloc::vec![lde]);
            let data = HidingFriPcsProverData::new(
                data,
                false,
                self.num_random_codewords,
                self.inner.fri.log_blowup,
            );
            main_attempt.finish()?;
            store.transition(Phase::MainCommitting, Phase::MainCommitted)?;
            Ok((root, data))
        })();
        match &result {
            Ok(_) => step.done = true,
            Err(e) => step.fail(e.clone()),
        }
        result
    }
    /// The retained implementation computes all eight normalized coupled masks.
    /// Its RNG guard spans its construction closures and their DFT operations.
    pub fn commit_composite_quotient<C>(
        &self,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
        evaluations: RowMajorMatrix<BabyBear>,
        chunks: usize,
    ) -> Result<CompositeCommitment<I>, CompositeError>
    where
        C: FieldChallenger<BabyBear>
            + GrindingChallenger<Witness = BabyBear>
            + CanObserve<I::Commitment>
            + CanObserve<F::Commitment>,
    {
        self.composite_profile()?;
        if domain.size() != 2048
            || domain.shift() != BabyBear::GENERATOR
            || evaluations.height() != 2048
            || evaluations.width() != 4
            || evaluations.values.len() != 8192
            || chunks != 8
        {
            return Err(CompositeError::Shape);
        }
        let shifts: [BabyBear; 8] = domain
            .split_domains(chunks)
            .into_iter()
            .map(|d| BabyBear::GENERATOR / d.shift())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| CompositeError::Shape)?;
        let store = &self.inner.storage;
        store.quotient_start(shifts)?;
        let mut step = Step::new(store);
        let result: Result<_, CompositeError> = (|| {
            let result = <Self as UnivariateStarkPcs<E4, C>>::commit_quotient(
                self,
                domain,
                evaluations,
                chunks,
            )
            .map_err(CompositeError::Mask)?;
            store.transition(Phase::QuotientCommitting, Phase::QuotientCommitted)?;
            Ok(result)
        })();
        match &result {
            Ok(_) => step.done = true,
            Err(e) => step.fail(e.clone()),
        }
        result
    }
    /// The actual auxiliary sampler runs once. It has no extra main masking.
    pub fn commit_composite_auxiliary<C>(
        &self,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
    ) -> Result<CompositeCommitment<I>, CompositeError>
    where
        C: FieldChallenger<BabyBear>
            + GrindingChallenger<Witness = BabyBear>
            + CanObserve<I::Commitment>
            + CanObserve<F::Commitment>,
    {
        self.composite_profile()?;
        if domain.size() != 512 || domain.shift() != BabyBear::ONE {
            return Err(CompositeError::Domain);
        }
        let store = &self.inner.storage;
        store.transition(Phase::QuotientCommitted, Phase::AuxiliaryBuilding)?;
        let mut step = Step::new(store);
        let result: Result<_, CompositeError> = (|| {
            let result =
                <Self as UnivariateStarkPcs<E4, C>>::get_opt_randomization_poly_commitment(
                    self,
                    [domain],
                )
                .map_err(CompositeError::Mask)?
                .ok_or(CompositeError::Incomplete)?;
            store.transition(Phase::AuxiliaryCommitting, Phase::AuxiliaryCommitted)?;
            Ok(result)
        })();
        match &result {
            Ok(_) => step.done = true,
            Err(e) => step.fail(e.clone()),
        }
        result
    }
}
