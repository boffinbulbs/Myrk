// This suffix belongs to the fresh nominal context module. Its retained
// constructor moves the PCS into the fresh owner before any raw input.
// No original dense prove() method belongs to this construction-only context.

use crate::{
    HidingFriPcsProverData,
    composite::{ProvingAttempt, QuotientInput, Step, Stored},
    quotient_kernel::{self, KernelError, Parameters, ReadFailure},
};
use kova_source_extension::reference_air::QuarticAir;
use p3_air::{BaseAir, symbolic::AirLayout};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{Field, PrimeCharacteristicRing, coset::TwoAdicMultiplicativeCoset};
use p3_uni_stark::{StarkProverTranscript, StarkShape, get_log_num_quotient_chunks_for_domain};

#[derive(Debug)]
pub(crate) enum ConstructionError {
    Owner(OwnedError),
    Kernel(KernelError<Error, Error>),
}
impl core::fmt::Display for ConstructionError {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Owner(error) => write!(out, "owned construction: {error:?}"),
            Self::Kernel(KernelError::Input(ReadFailure::ShortWindow {
                row,
                expected,
                actual,
            })) => write!(
                out,
                "quotient row {row}: expected {expected} fields, received {actual}"
            ),
            Self::Kernel(error) => write!(out, "quotient evaluation: {error:?}"),
        }
    }
}
impl From<OwnedError> for ConstructionError {
    fn from(error: OwnedError) -> Self {
        Self::Owner(error)
    }
}
impl From<Error> for ConstructionError {
    fn from(error: Error) -> Self {
        Self::Owner(OwnedError::from(error))
    }
}

/// Unopened main data and sealed quotient evaluations from one owned attempt.
/// This is private construction data, not a proof or verifier acceptance.
/// The attempt is last so field descriptors close before its final lease.
pub(crate) struct Construction<'ctx, D, I: Mmcs<BabyBear>, F, R, C> {
    quotient: QuotientInput,
    main_data: HidingFriPcsProverData<I::ProverData<Stored>>,
    main_commitment: I::Commitment,
    quotient_domain: TwoAdicMultiplicativeCoset<BabyBear>,
    config: &'ctx OwnedConfig<D, I, F, R, C>,
    store: &'ctx CompositeStore,
    _attempt: ProvingAttempt,
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
    /// The sole relation here is the unchanged retained QuarticAir256x2.
    /// No caller AIR, alpha, root, domain, matrix, filename or success callback.
    pub(crate) fn construct_quotient(
        &self,
        values: impl IntoIterator<Item = BabyBear>,
    ) -> Result<Construction<'_, D, I, F, R, C>, ConstructionError> {
        if cfg!(debug_assertions) {
            return Err(OwnedError::ReleaseRequired.into());
        }
        let config = &self.config;
        let pcs = config.pcs();
        pcs.composite_profile()?;
        if config.ood_proof_of_work_bits() != 0
            || config.lookup_proof_of_work_bits() != 0
            || config.is_zk() != 1
        {
            return Err(OwnedError::Context.into());
        }
        let raw = self.store.write_raw(values)?;
        let attempt = self.store.begin_attempt(&raw)?;
        let mut step = Step::new(&self.store);
        let result: Result<_, ConstructionError> = (|| {
            let air = &QuarticAir;
            let public = [BabyBear::from_u32(5), BabyBear::from_u32(260)];
            if <QuarticAir as BaseAir<BabyBear>>::width(air) != 2
                || <QuarticAir as BaseAir<BabyBear>>::num_public_values(air) != 2
                || <QuarticAir as BaseAir<BabyBear>>::preprocessed_width(air) != 0
                || !<QuarticAir as BaseAir<BabyBear>>::public_boundary_io(air).is_empty()
            {
                return Err(OwnedError::Context.into());
            }
            let layout = AirLayout {
                main_width: 2,
                num_public_values: 2,
                ..Default::default()
            };
            let trace_domain = <_ as Pcs<Challenge, C>>::natural_domain_for_degree(pcs, 256);
            let log_chunks = get_log_num_quotient_chunks_for_domain::<BabyBear, QuarticAir>(
                air,
                layout,
                trace_domain,
                config.is_zk(),
            );
            if log_chunks != 2
                || trace_domain.size() != 256
                || trace_domain.shift() != BabyBear::ONE
            {
                return Err(OwnedError::Context.into());
            }
            let extended_domain = <_ as Pcs<Challenge, C>>::natural_domain_for_degree(pcs, 512);
            let quotient_domain = extended_domain.create_disjoint_domain(2048);
            if extended_domain.shift() != BabyBear::ONE
                || extended_domain.size() != 512
                || quotient_domain.shift() != BabyBear::GENERATOR
                || quotient_domain.size() != 2048
            {
                return Err(OwnedError::Context.into());
            }
            let mut challenger = config.initialise_challenger();
            let (main_commitment, main_data) = pcs.commit_composite_main(extended_domain, raw)?;
            let mut transcript = StarkProverTranscript::<C, BabyBear, Challenge>::new(
                &mut challenger,
                StarkShape::new::<BabyBear, QuarticAir>(air, 0, 9, 8, 8, true, 0),
            );
            // This is the actual main commitment and the original transcript
            // operation. An externally supplied alpha cannot enter this path.
            let alpha = transcript.constraint_phase::<I::Commitment>(
                main_commitment.clone(),
                None,
                &public,
            );
            let evaluations = (|| {
                let view = pcs.main_quotient_view(&main_data, quotient_domain)?;
                let mut sink = self.store.begin_quotient_evaluations()?;
                let generated = quotient_kernel::generate::<OwnedConfig<D, I, F, R, C>, _, _, _>(
                    air,
                    Parameters {
                        public: &public,
                        trace_domain,
                        quotient_domain,
                        alpha,
                    },
                    &view,
                    &mut sink,
                );
                let written = match generated {
                    Ok(written) => written,
                    Err(error) => {
                        let cause = match &error {
                            KernelError::Input(ReadFailure::Access(cause))
                            | KernelError::Output(cause) => cause.clone(),
                            KernelError::Unsupported => Error::Unsupported,
                            KernelError::Domain => Error::Domain,
                            KernelError::Input(ReadFailure::ShortWindow { .. })
                            | KernelError::Shape
                            | KernelError::Layout => Error::Shape,
                        };
                        // Record the real normal-error cause while the sink is
                        // still live. Its destructor is the unwind fallback.
                        sink.abort(cause);
                        return Err(ConstructionError::Kernel(error));
                    }
                };
                if written != 2048 {
                    sink.abort(Error::Incomplete);
                    return Err(OwnedError::Context.into());
                }
                sink.finish().map_err(ConstructionError::from)
            })();
            let quotient = match evaluations {
                Ok(input) => input,
                Err(error) => {
                    transcript.abort();
                    return Err(error);
                }
            };
            // This construction-only branch intentionally abandons the complete
            // transcript. Abort releases its completeness drop check and never
            // rewinds the sponge. The challenger is diagnostic prefix state,
            // not a resumable or completed proof transcript.
            transcript.abort();
            drop(transcript);
            Ok((quotient, main_data, main_commitment, quotient_domain))
        })();
        // Keep the attempt outside the fallible closure. Its destructor must
        // not replace the first typed failure with a generic unwind marker.
        match result {
            Ok((quotient, main_data, main_commitment, quotient_domain)) => {
                step.done = true;
                Ok(Construction {
                    quotient,
                    main_data,
                    main_commitment,
                    quotient_domain,
                    config,
                    store: &self.store,
                    _attempt: attempt,
                })
            }
            Err(error) => {
                if let ConstructionError::Owner(OwnedError::Storage { source, .. }) = &error {
                    step.fail(source.clone());
                } else {
                    step.fail(Error::Incomplete);
                }
                Err(error)
            }
        }
    }
}

// ConstructionError is private. The original public OwnedError is unchanged.
// A returned Construction keeps the attempt live. Dropping it normally closes
// access because no actual proof was produced. There is no finish_produced call.

include!("diagnostics.rs");
