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

impl<D, I, F, R, S> HidingFriPcs<BabyBear, D, I, F, R, S>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
    pub(crate) fn composite_profile(&self) -> Result<(), CompositeError> {
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
}
impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
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
}

// This suffix belongs inside the fresh nominal hiding_pcs module, after the
// retained include and fixed main commitment implementation. No public factory.
use crate::quotient_kernel::CommittedRead;

/// A borrowed logical view of the actual main MMCS data. Fields stay private.
/// The immutable reference keeps the original prover data alive without cloning
/// the PCS, MMCS, RNG, configuration or the single-opening authority.
pub(crate) struct MainQuotientView<'a> {
    matrix: &'a Stored,
    opened: &'a AtomicBool,
}

impl MainQuotientView<'_> {
    fn available(&self) -> Result<(), CompositeError> {
        self.matrix.check_readable()?;
        if self.opened.load(Ordering::Acquire) {
            return Err(CompositeError::Closed);
        }
        Ok(())
    }
}

impl CommittedRead for MainQuotientView<'_> {
    type Error = CompositeError;

    fn dimensions(&self) -> Result<[usize; 2], Self::Error> {
        self.available()?;
        Ok([2048, 2])
    }

    fn read_window(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> Result<Vec<BabyBear>, Self::Error> {
        self.available()?;
        if row >= 2048 || start > end || end > 2 {
            return Err(CompositeError::Shape);
        }
        // The retained fast view truncates to the quotient-domain prefix first,
        // then reverses its 11-bit row index. Reversing 12 bits would read the
        // wrong points. Columns 2..6 are the four random codewords and stay hidden.
        let physical = p3_util::reverse_bits_len(row, 11);
        let values = self.matrix.try_window(physical, start, end)?;
        // A failure/opening during I/O must not return newly available values.
        // This is an access recheck, not physical cancellation of in-flight I/O.
        self.available()?;
        Ok(values)
    }
}

impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
    /// Read the actual committed matrix family. No caller matrix or path enters
    /// this constructor, and unsupported domains never reach the dense fallback.
    pub(crate) fn main_quotient_view<'a>(
        &self,
        data: &'a HidingFriPcsProverData<I::ProverData<Stored>>,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
    ) -> Result<MainQuotientView<'a>, CompositeError> {
        let store = &self.inner.storage;
        let mut step = Step::new(store);
        let result = (|| {
            self.composite_profile()?;
            if domain.size() != 2048 || domain.shift() != BabyBear::GENERATOR {
                return Err(CompositeError::Domain);
            }
            store.check_phase(Phase::MainCommitted)?;
            if data.preprocessed
                || data.num_random_codewords != 4
                || data.log_blowup != 3
                || data.opened.load(Ordering::Acquire)
            {
                return Err(CompositeError::Closed);
            }
            let matrices = self.inner.mmcs.get_matrices(&data.inner);
            if matrices.len() != 1 {
                return Err(CompositeError::Shape);
            }
            let matrix = matrices[0];
            store.check_committed_main(matrix)?;
            let view = MainQuotientView {
                matrix,
                opened: &data.opened,
            };
            view.available()?;
            Ok(view)
        })();
        match &result {
            Ok(_) => step.done = true,
            Err(error) => step.fail(error.clone()),
        }
        result
    }
}

// Derived from the retained HidingFriPcs quotient mapper and commitment entry.
// This suffix belongs to a fresh module containing the original backend include.
// Original MIT and Apache 2.0 notices accompany the eventual derived package.
use crate::composite::QuotientInput;

impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
    /// Consume the same owner's completed quotient source. No caller matrix,
    /// root, challenge, output path or acceptance predicate enters this method.
    pub(crate) fn commit_quotient_source(
        &self,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
        source: QuotientInput,
    ) -> Result<CompositeCommitment<I>, CompositeError> {
        self.composite_profile()?;
        let store = &self.inner.storage;
        store.check_quotient_input(&source)?;
        store.check_phase(Phase::QuotientReady)?;
        if domain.size() != 2048 || domain.shift() != BabyBear::GENERATOR {
            return Err(CompositeError::Domain);
        }
        if source.dimensions()? != [2048, 4] {
            return Err(CompositeError::Shape);
        }
        self.check_hiding_budget(256, 4, 1)
            .map_err(CompositeError::Mask)?;
        let domains = domain.split_domains(8);
        if domains.len() != 8 || domains.iter().any(|d| d.size() != 256) {
            return Err(CompositeError::Shape);
        }
        let shifts: [BabyBear; 8] = domains
            .iter()
            .map(|d| BabyBear::GENERATOR / d.shift())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| CompositeError::Shape)?;
        // The exclusive claim occurs before private entropy is sampled. A
        // second claimant cannot acquire a second RNG construction interval.
        store.begin_quotient_source(&source, shifts)?;
        let mut step = Step::new(store);
        let result = (|| {
            // Use the actual retained normalization before locking the RNG.
            let cis = get_zp_cis(&domains);
            if cis.len() != 8 {
                return Err(CompositeError::Shape);
            }
            let last_inverse = cis[7].inverse();
            let multipliers = (0..7).map(|i| cis[i] * last_inverse).collect::<Vec<_>>();
            let ldes = {
                // Retain the original guard through all eight constructions.
                // This is the RNG mutex, never the owner state mutex.
                let mut rng = self.rng.lock();
                // with_random_cols samples chunk, row, trailing column in this
                // order. Store only its random columns, not all widened inputs.
                let random_columns = (0..8 * 256 * 4)
                    .map(|_| rng.random::<BabyBear>())
                    .collect::<Vec<_>>();
                let mut masks = (0..7 * 256 * 8)
                    .map(|_| rng.random::<BabyBear>())
                    .chain(core::iter::repeat_n(BabyBear::ZERO, 256 * 8))
                    .collect::<Vec<_>>();
                couple_mask_banks(&multipliers, &mut masks)?;
                let mut outputs = Vec::with_capacity(8);
                for i in 0..8 {
                    let mut values = Vec::with_capacity(256 * 8);
                    for row in 0..256 {
                        // split_evals distributes interleaved logical rows.
                        // Reads happen after entropy, so failures close the
                        // owner without rewinding or retrying that RNG stream.
                        let fields = source.try_window(8 * row + i, 0, 4)?;
                        if fields.len() != 4 {
                            return Err(CompositeError::Shape);
                        }
                        values.extend_from_slice(&fields);
                        let start = (i * 256 + row) * 4;
                        values.extend_from_slice(&random_columns[start..start + 4]);
                    }
                    let evaluations = RowMajorMatrix::new(values, 8);
                    let stored = store.extend_quotient_owned(
                        &self.inner.dft,
                        evaluations,
                        &masks[i * 256 * 8..(i + 1) * 256 * 8],
                        3,
                        shifts[i],
                    )?;
                    outputs.push(stored);
                }
                outputs
            };
            // As in the retained mapper, release the mask RNG before MMCS.
            if ldes.len() != 8 {
                return Err(CompositeError::Incomplete);
            }
            for lde in &ldes {
                if lde.height() != 4096 || lde.width() != 8 {
                    return Err(CompositeError::Shape);
                }
                self.check_hiding_budget(self.lde_mask_height(lde.height()), 4, 1)
                    .map_err(CompositeError::Mask)?;
            }
            store.check_phase(Phase::QuotientCommitting)?;
            let (root, data) = self.inner.commit_stored_ldes(ldes);
            let data = HidingFriPcsProverData::new(data, false, 4, 3);
            store.transition(Phase::QuotientCommitting, Phase::QuotientCommitted)?;
            Ok((root, data))
        })();
        match &result {
            Ok(_) => step.done = true,
            Err(error) => step.fail(error.clone()),
        }
        result
    }
}

// Exact fixed-shape extraction of the original coupled update loop. The actual
// source-consuming adapter and the normalization diagnostic use this function.
// It samples no randomness and accepts no expected values or verdict callback.
fn couple_mask_banks(
    multipliers: &[BabyBear],
    masks: &mut [BabyBear],
) -> Result<(), CompositeError> {
    if multipliers.len() != 7 || masks.len() != 8 * 256 * 8 {
        return Err(CompositeError::Shape);
    }
    for j in 0..7 {
        for k in 0..256 * 8 {
            let term = masks[j * 256 * 8 + k] * multipliers[j];
            masks[7 * 256 * 8 + k] -= term;
        }
    }
    Ok(())
}

// Exact original auxiliary entry body for a future fresh hiding module.
// The corresponding original MIT and Apache notices accompany this fragment.
impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpeningCase {
    ExcessPoints,
    SharedPrivateRequests,
}
pub(crate) struct OpeningObservation {
    pub cause: CompositeError,
    pub lease: Stored,
    pub original_opened: bool,
    pub clone_opened: bool,
}

impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    I::ProverData<Stored>: Clone,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
    pub(crate) fn private_opening_control<C>(
        &self,
        data: &HidingFriPcsProverData<I::ProverData<Stored>>,
        challenger: &mut C,
        selected: OpeningCase,
    ) -> OpeningObservation
    where
        C: FieldChallenger<BabyBear>
            + GrindingChallenger<Witness = BabyBear>
            + CanObserve<I::Commitment>
            + CanObserve<F::Commitment>
            + p3_challenger::CanSample<E4>
            + Clone,
    {
        self.composite_profile().unwrap();
        self.inner
            .storage
            .check_phase(Phase::MainCommitted)
            .unwrap();
        assert!(!data.preprocessed && !data.opened.load(Ordering::Acquire));
        let matrices = self.inner.mmcs.get_matrices(&data.inner);
        assert_eq!(matrices.len(), 1);
        self.inner
            .storage
            .check_committed_main(matrices[0])
            .unwrap();
        let lease = matrices[0].clone();
        let alias = data.clone();
        assert!(Arc::ptr_eq(&data.opened, &alias.opened));
        let before: E4 = challenger.clone().sample_algebra_element();
        let point = E4::from_u32(7);
        let cause = match selected {
            OpeningCase::ExcessPoints => {
                let result = <Self as Pcs<E4, C>>::open(
                    self,
                    vec![OpeningRequest {
                        prover_data: &alias,
                        points: vec![vec![point; 17]],
                    }],
                    challenger,
                );
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("excess actual opening points must fail preflight"),
                };
                assert_eq!(
                    error,
                    HidingFriProverError::HidingBudgetExceeded {
                        mask_height: 256,
                        num_queries: 64,
                        num_opening_points: 17,
                        extension_degree: 4,
                    }
                );
                assert!(!data.opened.load(Ordering::Acquire));
                assert!(!alias.opened.load(Ordering::Acquire));
                CompositeError::Mask(error)
            }
            OpeningCase::SharedPrivateRequests => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    <Self as Pcs<E4, C>>::open(
                        self,
                        vec![
                            OpeningRequest {
                                prover_data: data,
                                points: vec![vec![point]],
                            },
                            OpeningRequest {
                                prover_data: &alias,
                                points: vec![vec![point]],
                            },
                        ],
                        challenger,
                    )
                }));
                let payload = match result {
                    Err(payload) => payload,
                    Ok(_) => {
                        panic!("shared private requests must hit the original consumption guard")
                    }
                };
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied());
                assert_eq!(
                    message,
                    Some("private hiding commitment was already opened; recommit with fresh masks")
                );
                assert!(data.opened.load(Ordering::Acquire));
                assert!(alias.opened.load(Ordering::Acquire));
                CompositeError::Unwind
            }
        };
        let after: E4 = challenger.clone().sample_algebra_element();
        assert_eq!(before, after);
        OpeningObservation {
            cause,
            lease,
            original_opened: data.opened.load(Ordering::Acquire),
            clone_opened: alias.opened.load(Ordering::Acquire),
        }
    }
}

impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
    pub(crate) fn main_opening_unused(
        &self,
        data: &HidingFriPcsProverData<I::ProverData<Stored>>,
    ) -> bool {
        !data.preprocessed
            && data.num_random_codewords == self.num_random_codewords
            && data.log_blowup == self.inner.fri.log_blowup
            && !data.opened.load(Ordering::Acquire)
    }
    /// Borrow real returned data and retain only an actual checked lease plus
    /// bounded field observations. No expected values enter this method.
    pub(crate) fn observe_main_data(
        &self,
        data: &HidingFriPcsProverData<I::ProverData<Stored>>,
    ) -> Result<(Stored, Vec<BabyBear>), CompositeError> {
        self.composite_profile()?;
        if !self.main_opening_unused(data) {
            return Err(CompositeError::Closed);
        }
        let matrices = self.inner.mmcs.get_matrices(&data.inner);
        if matrices.len() != 1 {
            return Err(CompositeError::Shape);
        }
        let matrix = matrices[0];
        self.inner.storage.check_committed_main(matrix)?;
        let mut fields = Vec::with_capacity(4096 * 6);
        for row in 0..4096 {
            let values = matrix.try_window(row, 0, 6)?;
            if values.len() != 6 {
                return Err(CompositeError::Shape);
            }
            fields.extend(values);
        }
        self.inner.storage.check_committed_main(matrix)?;
        if fields.len() != 4096 * 6 || !self.main_opening_unused(data) {
            return Err(CompositeError::Closed);
        }
        Ok(((*matrix).clone(), fields))
    }
}
