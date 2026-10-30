#![forbid(unsafe_code)]
// The included verifier retains its original boolean expression.
#![allow(clippy::nonminimal_bool)]
include!("../../storage-pcs/backend/src/hiding_pcs.rs");

use crate::source::{Challenge, Error as SourceError, Input, RawInput, SourceStore, Stored};
use p3_baby_bear::BabyBear;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

pub type SourceCommitment<I> = (
    <I as Mmcs<BabyBear>>::Commitment,
    HidingFriPcsProverData<<I as Mmcs<BabyBear>>::ProverData<Stored>>,
);

impl<D, I, F, R> HidingFriPcs<BabyBear, D, I, F, R, SourceStore>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear>,
    F: Mmcs<Challenge>,
    R: CryptoRng + Send + Sync,
{
    fn source_profile(
        &self,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
    ) -> Result<(), SourceError> {
        if domain.size() != 512 || domain.shift() != BabyBear::ONE {
            return Err(SourceError::Domain);
        }
        let fri = &self.inner.fri;
        if self.num_random_codewords != 4
            || fri.num_queries != 64
            || fri.log_blowup != 3
            || fri.log_final_poly_len != 0
            || fri.max_log_arity != 1
            || [
                fri.batch_proof_of_work_bits,
                fri.commit_proof_of_work_bits,
                fri.query_proof_of_work_bits,
            ] != [0; 3]
        {
            return Err(SourceError::Profile);
        }
        self.check_hiding_budget(256, <Challenge as BasedVectorSpace<BabyBear>>::DIMENSION, 2)
            .map_err(SourceError::Mask)
    }
    /// Owned input is supplied through its checked internal handle.
    /// This is a genuine stored-LDE commitment,
    /// not an opening proof or a proof of the input's AIR validity.
    pub fn commit_owned_source(
        &self,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
        raw: RawInput,
    ) -> Result<SourceCommitment<I>, SourceError> {
        self.source_profile(domain)?;
        self.inner.storage.check_raw(&raw)?;
        self.commit_source(Input::Owned(raw))
    }
    /// Dense convenience uses the same preparation and commitment pipeline.
    /// The original ordinary Pcs::commit entry remains unchanged.
    pub fn commit_dense_source(
        &self,
        domain: TwoAdicMultiplicativeCoset<BabyBear>,
        matrix: RowMajorMatrix<BabyBear>,
    ) -> Result<SourceCommitment<I>, SourceError> {
        self.source_profile(domain)?;
        if matrix.width != 2 || matrix.values.len() != 512 {
            return Err(SourceError::Shape);
        }
        self.commit_source(Input::Dense(matrix))
    }
    fn commit_source(&self, input: Input) -> Result<SourceCommitment<I>, SourceError> {
        let mut attempt = self
            .inner
            .storage
            .begin(matches!(&input, Input::Dense(_)))?;
        let result: Result<_, SourceError> = (|| {
            let prepared = {
                let mut rng = self.rng.lock();
                match input {
                    Input::Owned(raw) => self.inner.storage.prepare_owned(raw, &mut *rng)?,
                    Input::Dense(matrix) => self.inner.storage.prepare_dense(matrix, &mut *rng)?,
                }
            };
            let lde = self.inner.storage.extend(prepared, &self.inner.dft)?;
            self.inner.storage.committing()?;
            let (root, data) = self.inner.commit_stored_ldes(alloc::vec![lde]);
            let data = HidingFriPcsProverData::new(
                data,
                false,
                self.num_random_codewords,
                self.inner.fri.log_blowup,
            );
            attempt.finish()?;
            Ok((root, data))
        })();
        if let Err(error) = &result {
            attempt.fail(error.clone());
        }
        result
    }
}
