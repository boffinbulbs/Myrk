// Included in the fresh hiding module, preserving its private data ownership.
impl<V, D, I, M, R, S, E, C> crate::domain::Geometry<E, C> for HidingFriPcs<V, D, I, M, R, S>
where
    V: TwoAdicField + PrimeField64,
    StandardUniform: Distribution<V>,
    E: TwoAdicField + ExtensionField<V>,
    D: TwoAdicSubgroupDft<V>,
    I: Mmcs<V, MultiProof: Sync, Error: Sync>,
    M: Mmcs<E>,
    R: CryptoRng + Send + Sync,
    S: MatrixStore<V>,
    C: FieldChallenger<V> + CanObserve<M::Commitment> + GrindingChallenger<Witness = V>,
{
    fn admit_prover(
        &self,
        rounds: &[OpeningRequest<'_, Self::ProverData, E>],
    ) -> Result<(), crate::domain::DomainError> {
        use crate::domain::DomainError;
        if rounds.is_empty() {
            return Err(DomainError::NoCommitments);
        }
        for (batch, round) in rounds.iter().enumerate() {
            let data = round.prover_data;
            if data.num_random_codewords != self.num_random_codewords
                || data.log_blowup != self.inner.fri.log_blowup
            {
                return Err(DomainError::Configuration { batch });
            }
            let matrices = self.inner.mmcs.get_matrices(&data.inner);
            crate::domain::matrices::<V, E, S::Stored>(&matrices, &round.points, batch)?;
        }
        Ok(())
    }
    fn admit_verifier(
        &self,
        rounds: &[CommitmentOpening<E, Self::Commitment, Self::Domain>],
    ) -> Result<(), crate::domain::DomainError> {
        crate::domain::claims(rounds, self.inner.fri.log_blowup)
    }
}

impl<D, I, F, R> crate::domain::OpeningChecked<HidingFriPcs<BabyBear, D, I, F, R, CompositeStore>>
where
    D: TwoAdicSubgroupDft<BabyBear>,
    I: Mmcs<BabyBear, MultiProof: Sync, Error: Sync>,
    F: Mmcs<E4>,
    R: CryptoRng + Send + Sync,
{
    pub(crate) fn composite_profile(&self) -> Result<(), CompositeError> {
        self.retained().composite_profile()
    }

    pub(crate) fn domain_opened(
        &self,
        data: &HidingFriPcsProverData<I::ProverData<Stored>>,
    ) -> bool {
        data.opened.load(Ordering::Acquire)
    }

    pub(crate) fn domain_lease(
        &self,
        data: &HidingFriPcsProverData<I::ProverData<Stored>>,
    ) -> Result<Stored, CompositeError> {
        let inner = self.retained();
        let matrices = inner.inner.mmcs.get_matrices(&data.inner);
        if matrices.len() != 1 {
            return Err(CompositeError::Shape);
        }
        inner.inner.storage.check_committed_main(matrices[0])?;
        Ok(matrices[0].clone())
    }
}
