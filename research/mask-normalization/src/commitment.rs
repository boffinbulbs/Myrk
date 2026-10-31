// One source-consuming commitment component. The earlier diagnostic transcript
// prefix is aborted, so this component never claims a resumed STARK transcript.
pub(crate) struct Committed<'ctx, D, I: Mmcs<BabyBear>, F, R, C> {
    main_data: HidingFriPcsProverData<I::ProverData<Stored>>,
    quotient_data: HidingFriPcsProverData<I::ProverData<Stored>>,
    main_commitment: I::Commitment,
    quotient_commitment: I::Commitment,
    config: &'ctx OwnedConfig<D, I, F, R, C>,
    _attempt: ProvingAttempt,
}

impl<'ctx, D, I, F, R, C> Construction<'ctx, D, I, F, R, C>
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
    fn commit(self) -> Result<Committed<'ctx, D, I, F, R, C>, Error> {
        let Self {
            quotient,
            main_data,
            main_commitment,
            quotient_domain,
            config,
            store,
            _attempt: attempt,
        } = self;
        let mut step = Step::new(store);
        let result = config
            .pcs()
            .commit_quotient_source(quotient_domain, quotient);
        match result {
            Ok((quotient_commitment, quotient_data)) => {
                step.done = true;
                Ok(Committed {
                    main_data,
                    quotient_data,
                    main_commitment,
                    quotient_commitment,
                    config,
                    _attempt: attempt,
                })
            }
            Err(error) => {
                step.fail(error.clone());
                Err(error)
            }
        }
    }
}
