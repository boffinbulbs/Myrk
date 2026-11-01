//! Owned input adaptation of the pinned upstream uni STARK prover.
//! Original upstream licenses and attribution are retained in NOTICE.md.
#![forbid(unsafe_code)]

use crate::extension::reference_air::QuarticAir;
use crate::{
    composite::{Challenge, CompositeStore, Error, RawInput, Step},
    context::OwnedError,
    owned_pcs::OwnedPcs,
    quotient_kernel::{self, KernelError, Parameters, ReadFailure},
};
use alloc::vec;
use itertools::Itertools;
use p3_air::{
    BaseAir,
    symbolic::{AirLayout, get_symbolic_constraints},
};
use p3_baby_bear::BabyBear;
use p3_challenger::GrindingChallenger;
use p3_commit::{Pcs, PolynomialSpace, UnivariateStarkPcs};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{
    Com, Commitments, OpenedValues, PreprocessedOpenedValues, PreprocessedProverData, Proof,
    ProvingError, QuotientAir, StarkGenericConfig, StarkProverTranscript, StarkShape, Val,
    get_log_num_quotient_chunks_for_domain,
};
use p3_util::log2_strict_usize;
use tracing::info_span;

pub(crate) fn prove_owned<SC>(
    config: &SC,
    store: &CompositeStore,
    trace: RawInput,
) -> Result<Proof<SC>, OwnedError>
where
    SC: StarkGenericConfig<Challenge = Challenge>,
    SC::Challenger: GrindingChallenger<Witness = BabyBear>,
    SC::Pcs: OwnedPcs<SC::Challenger>,
    QuarticAir: QuotientAir<SC>,
{
    let air = &QuarticAir;
    let public_values = &[BabyBear::from_u32(5), BabyBear::from_u32(260)];
    let preprocessed: Option<&PreprocessedProverData<SC>> = None;
    let mut attempt = store.begin_attempt(&trace)?;
    let mut step = Step::new(store);
    let result: Result<Proof<SC>, OwnedError> = (|| {
        // Public inputs reach this proof only through AIR constraints.
        // A cell listed for backend binding would go completely unbound.
        assert!(
            <QuarticAir as BaseAir<BabyBear>>::public_boundary_io(air).is_empty(),
            "uni-stark does not support boundary-IO public values; bind them with AIR constraints"
        );

        // Compute the height `N = 2^n` and `log_2(height)`, `n`, of the trace.
        let degree = 256;
        let log_degree = log2_strict_usize(degree);
        let log_ext_degree = log_degree + config.is_zk();

        // Get preprocessed width for symbolic constraint evaluation.
        //
        // - If reusable preprocessed prover data is provided, trust its width and degree_bits
        //   (and enforce consistency).
        // - Otherwise, if the AIR defines preprocessed columns, we treat it as an error:
        //   callers must use `setup_preprocessed` and pass the resulting data in.
        let preprocessed_width = preprocessed.map_or_else(
            || {
                let width = <QuarticAir as BaseAir<BabyBear>>::preprocessed_width(air);
                if width > 0 {
                    panic!(
                        "AIR defines preprocessed columns (width = {width}), \
                     but no PreprocessedProverData was provided. \
                     Call `setup_preprocessed` and pass it to `prove_with_preprocessed`."
                    );
                }
                0
            },
            |pp| {
                assert_eq!(
                    pp.degree_bits, log_ext_degree,
                    "PreprocessedProverData degree_bits does not match trace degree_bits"
                );
                pp.width
            },
        );

        let layout = AirLayout {
            preprocessed_width,
            main_width: <QuarticAir as BaseAir<BabyBear>>::width(air),
            num_public_values: <QuarticAir as BaseAir<BabyBear>>::num_public_values(air),
            num_periodic_columns: <QuarticAir as BaseAir<BabyBear>>::num_periodic_columns(air),
            ..Default::default()
        };

        // In debug builds, cross-check the static hint against symbolic evaluation.
        debug_assert!(
            <QuarticAir as BaseAir<BabyBear>>::num_constraints(air).is_none_or(|n| {
                n == get_symbolic_constraints::<BabyBear, QuarticAir>(air, layout).len()
            }),
            "num_constraints() = {} but symbolic evaluation found {} constraints",
            <QuarticAir as BaseAir<BabyBear>>::num_constraints(air).unwrap(),
            get_symbolic_constraints::<BabyBear, QuarticAir>(air, layout).len(),
        );

        // Each constraint polynomial looks like `C_j(X_1, ..., X_w, Y_1, ..., Y_w, Z_1, ..., Z_j)`.
        // When evaluated on a given row, the X_i's will be the `i`'th element of the that row, the
        // Y_i's will be the `i`'th element of the next row and the Z_i's will be evaluations of
        // selector polynomials on the given row index.
        //
        // For two-adic domains, the `X_i`'s and `Y_i`'s will be replaced by the
        // degree `N - 1` polynomials `T_i(x)` and `T_i(hx)` respectively. The selector polynomials are
        // a little more complicated, however.
        //
        // In our case, the selector polynomials are `S_1(x) = is_first_row`, `S_2(x) = is_last_row`
        // and `S_3(x) = is_transition`. Both `S_1(x)` and `S_2(x)` are polynomials of degree `N - 1`
        // as they must be non-zero only at a single location in the initial domain. However,
        // `is_transition` is a polynomial of degree `1` as it simply needs to be `0` on the last row.
        //
        // The constraint degree (`deg(C)`) is the linear factor of `N` in the constraint polynomial. In other
        // words, it is roughly the total degree of `C`; however, we treat `Z_3` as a constant term which does
        // not contribute to the degree.
        //
        // E.g. `C_j = Z_1 * (X_1^3 - X_2 * X_3 * X_4)` would have degree `4`.
        //      `C_j = Z_3 * (X_1^3 - X_2 * X_3 * X_4)` would have degree `3`.
        //
        // The point of all this is that, defining:
        //          C(x) = C(T_1(x), ..., T_w(x), T_1(hx), ... T_w(hx), S_1(x), S_2(x), S_3(x))
        // We get the constraint bound:
        //          deg(C(x)) <= deg(C) * (N - 1) + 1
        // The `+1` assumes at most one `is_transition` factor per term. Circle instead
        // counts each transition factor at full trace-space degree.
        //
        // For now in comments we assume that `deg(C) = 3` meaning `deg(C(x)) <= 3N - 2`

        let pcs = config.pcs();
        // Get the subgroup `H` of size `N`, or a standard-position twin coset for Circle.
        let trace_domain = pcs.natural_domain_for_degree(degree);

        // From the degree of the constraint polynomial, compute the number
        // of quotient polynomials we will split Q(x) into. This is chosen to
        // always be a power of 2.
        let log_num_quotient_chunks = get_log_num_quotient_chunks_for_domain::<Val<SC>, QuarticAir>(
            air,
            layout,
            trace_domain,
            config.is_zk(),
        );

        let num_quotient_chunks = 1 << (log_num_quotient_chunks + config.is_zk());
        if degree != 256 || log_ext_degree != 9 || num_quotient_chunks != 8 {
            return Err(OwnedError::Context);
        }

        // Initialize the Challenger.
        let mut challenger = config.initialise_challenger();

        // When ZK is enabled, we need to use an extended domain of size `2N` as we will
        // add random values to the trace.
        let ext_trace_domain = pcs.natural_domain_for_degree(degree * (config.is_zk() + 1));

        // Let `g` denote a generator of the multiplicative group of `F` and `H'` the unique
        // subgroup of `F` of size `N << (pcs.config.log_blowup + config.is_zk())`.
        // If `zk` is enabled, we double the trace length by adding random values.
        //
        // For each trace column `T_i`, we compute the evaluation vector of `T_i(x)` over `H'`. This
        // new extended trace `ET` is hashed into a Merkle tree with its rows bit-reversed.
        //      trace_commit contains the root of the tree
        //      trace_data contains the entire tree.
        //          - trace_data.leaves is the matrix containing `ET`.
        let (trace_commit, trace_data) = info_span!("commit to trace data")
            .in_scope(|| pcs.commit_main_owned(ext_trace_domain, trace))
            .map_err(|source| OwnedError::Storage {
                phase: "trace commitment",
                source,
            })?;

        // Preprocessed commitment and prover data (if any).
        let (preprocessed_commit, preprocessed_data_ref) = preprocessed
            .map(|pp| (pp.commitment.clone(), &pp.prover_data))
            .unzip();

        // Describe the transcript before running it.
        //
        // Every number comes from the configuration and from the AIR, never from a proof.
        // The verifier builds the identical description from its own copies of both.
        let mut transcript = StarkProverTranscript::<SC::Challenger, Val<SC>, SC::Challenge>::new(
            &mut challenger,
            StarkShape::new::<Val<SC>, QuarticAir>(
                air,
                preprocessed_width,
                log_ext_degree,
                log_degree,
                num_quotient_chunks,
                SC::Pcs::ZK,
                config.ood_proof_of_work_bits(),
            ),
        );

        let stages: Result<_, OwnedError> = (|| {
            // Bind both committed traces and the public values, then draw the batching challenge.
            //
            // Soundness Error:
            // If a prover is malicious, we can find a row `i` such that some of the constraints
            // C_0, ..., C_n are non 0 on this row. The malicious prover "wins" if the random challenge
            // alpha is such that:
            // (1): C_0(i) + alpha * C_1(i) + ... + alpha^n * C_n(i) = 0
            // This is a polynomial of degree n, so it has at most n roots. Thus the probability of this
            // occurring for a given trace and set of constraints is n/|EF|.
            //
            // The AIR's shape reaches the seed through the transcript's own description.
            // A wider trace or another quotient chunk count therefore draws a different alpha.
            //
            // What the seed does not carry is the constraint polynomials themselves.
            // A prover may claim another AIR of the same shape without moving this sample.
            // The verifier evaluates the AIR it holds, so checking that AIR is its job regardless.
            let alpha = transcript.constraint_phase::<Com<SC>>(
                trace_commit.clone(),
                preprocessed_commit.filter(|_| preprocessed_width > 0),
                public_values,
            );

            // A domain large enough to uniquely identify the quotient polynomial.
            // This domain must be contained in the domain over which `trace_data` is defined.
            // Explicitly it should be equal to `gK` for some subgroup `K` contained in `H'`.
            let quotient_domain = ext_trace_domain
                .create_disjoint_domain(1 << (log_ext_degree + log_num_quotient_chunks));

            // Borrow the same owner's actual main data and seal canonical quotient
            // coefficients without materializing the old whole quotient Vec.
            let trace_view = pcs.main_quotient_view_owned(&trace_data, quotient_domain)?;
            let mut sink = store.begin_quotient_evaluations()?;
            let generated = quotient_kernel::generate::<SC, _, _, _>(
                air,
                Parameters {
                    public: public_values,
                    trace_domain,
                    quotient_domain,
                    alpha,
                },
                &trace_view,
                &mut sink,
            );
            let written = match generated {
                Ok(count) => count,
                Err(error) => {
                    let cause = match error {
                        KernelError::Input(ReadFailure::Access(cause))
                        | KernelError::Output(cause) => cause,
                        KernelError::Unsupported => Error::Unsupported,
                        KernelError::Domain => Error::Domain,
                        KernelError::Shape | KernelError::Layout => Error::Shape,
                        KernelError::Input(ReadFailure::ShortWindow {
                            row,
                            expected,
                            actual,
                        }) => {
                            tracing::error!(
                                row,
                                expected,
                                actual,
                                "short committed quotient window"
                            );
                            Error::Shape
                        }
                    };
                    sink.abort(cause.clone());
                    return Err(OwnedError::Storage {
                        phase: "quotient evaluation",
                        source: cause,
                    });
                }
            };
            if written != 2048 {
                sink.abort(Error::Incomplete);
                return Err(OwnedError::Storage {
                    phase: "quotient count",
                    source: Error::Incomplete,
                });
            }
            let quotient_source = sink.finish()?;

            // Currently each polynomial `Q_i(x)` is of degree `<= 2(N - 1)` and
            // we have it's evaluations over a the coset `gK of size `2N`. Let `k` be the chosen
            // generator of `K` which satisfies `k^2 = h`.
            //
            // We can split this coset into the sub-cosets `gH` and `gkH` each of size `N`.
            // Define:  L_g(x)    = (x^N - (gk)^N)/(g^N - (gk)^N) = (x^N + g^N)/2g^N
            //          L_{gk}(x) = (x^N - g^N)/(g^N - (gk)^N)    = -(x^N - g^N)/2g^N.
            // Then `L_g` is equal to `1` on `gH` and `0` on `gkH` and `L_{gk}` is equal to `1` on `gkH` and `0` on `gH`.
            //
            // Thus we can decompose `Q_i(x) = L_{g}(x)q_{i0}(x) + L_{gk}(x)q_{i1}(x)` (Or an randomized version of this in the zk case)
            // where `q_{i0}(x)` and `q_{i1}(x)` are polynomials of degree `<= N - 1`.
            // Moreover the evaluations of `q_{i0}(x), q_{i1}(x)` on `gH` and `gkH` respectively are
            // exactly the evaluations of `Q_i(x)` on `gH` and `gkH`.
            // For each polynomial `q_{ij}`, compute the evaluation vector of `q_{ij}(x)` over `gH'`. We bit
            // reverse the rows and hash the resulting matrix into a merkle tree.
            //      quotient_commit contains the root of the tree
            //      quotient_data contains the entire tree.
            //          - quotient_data.leaves is a pair of matrices containing the `q_i0(x)` and `q_i1(x)`.
            let (quotient_commit, quotient_data) = info_span!("commit to quotient poly chunks")
                .in_scope(|| pcs.commit_quotient_owned(quotient_domain, quotient_source))
                .map_err(|source| OwnedError::Storage {
                    phase: "quotient commitment",
                    source,
                })?;

            // If zk is enabled, we generate random extension field values of the size of the randomized trace. If `n` is the degree of the initial trace,
            // then the randomized trace has degree `2n`. To randomize the FRI batch polynomial, we then need an extension field random polynomial of degree `2n -1`.
            // So we can generate a random polynomial of degree `2n`, and provide it to `open` as is.
            // Then the method will add `(R(X) - R(z)) / (X - z)` (which is of the desired degree `2n - 1`), to the batch of polynomials.
            // Since we need a random polynomial defined over the extension field, and the `commit` method is over the base field,
            // we actually need to commit to `SC::Challenge::D` base field random polynomials.
            // This is similar to what is done for the quotient polynomials.
            // TODO: This approach is only statistically zk. To make it perfectly zk, `R` would have to truly be an extension field polynomial.
            let (opt_r_commit, opt_r_data) = if SC::Pcs::ZK {
                let (r_commit, r_data) = pcs
                    .commit_auxiliary_owned(ext_trace_domain)
                    .map_err(|source| OwnedError::Storage {
                        phase: "randomization commitment",
                        source,
                    })?
                    .expect("ZK is enabled, so we should have randomization commitments");
                (Some(r_commit), Some(r_data))
            } else {
                (None, None)
            };

            // Combine our commitments to the trace and quotient polynomials into a single object which
            // will be passed to the verifier.
            let commitments = Commitments {
                trace: trace_commit,
                quotient_chunks: quotient_commit,
                random: opt_r_commit.clone(),
            };

            // Bind the quotient chunks and any randomization polynomial, grind, then draw the point.
            //
            // Soundness Error:
            // This sample will be used to check the equality: `C(X) = ZH(X)Q(X)`. If a prover is malicious
            // and this equality is false, the probability that it is true at the point `zeta` will be
            // deg(C(X))/|EF| = dN/|EF| where `N` is the trace length and our constraints have degree `d`.
            //
            // Completeness Error:
            // If zeta happens to lie in the domain `gK`, then when opening at zeta we will run into division
            // by zero errors. This doesn't lead to a soundness issue as the verifier will just reject in those
            // cases but it is a completeness issue and contributes a completeness error of |gK| = 2N/|EF|.
            //
            // Grinding before the sample makes each attempt at a favourable `zeta` cost
            // `2^ood_proof_of_work_bits` work, adding that many bits to the round's error above. `dN/|EF|`
            // is fixed by the AIR and the trace height, so this grind is the only parameter that moves it.
            let (zeta, ood_pow_witness) =
                transcript.ood_phase::<Com<SC>>(commitments.quotient_chunks.clone(), opt_r_commit);
            // A zero difficulty still occupies a slot in the proof, keeping its shape fixed.
            let ood_pow_witness = ood_pow_witness.unwrap_or(Val::<SC>::ZERO);
            let zeta_next = trace_domain
                .next_point(zeta)
                .expect("domain should support next_point operation");

            let is_random = opt_r_data.is_some();
            let main_next =
                !<QuarticAir as BaseAir<BabyBear>>::main_next_row_columns(air).is_empty();
            let pre_next =
                !<QuarticAir as BaseAir<BabyBear>>::preprocessed_next_row_columns(air).is_empty();
            let opening_layout = p3_uni_stark::StarkOpeningLayout::new(SC::Pcs::ZK);
            attempt.begin_opening()?;
            let opening_result = info_span!("open").in_scope(|| {
                let round0 = opt_r_data.as_ref().map(|r_data| (r_data, vec![vec![zeta]]));
                let round1_points = if main_next {
                    vec![zeta, zeta_next]
                } else {
                    vec![zeta]
                };
                let round1 = (&trace_data, vec![round1_points]);
                let round2 = (&quotient_data, vec![vec![zeta]; num_quotient_chunks]); // open every chunk at zeta
                let round3 = preprocessed_data_ref.map(|data| {
                    let pre_points = if pre_next {
                        vec![zeta, zeta_next]
                    } else {
                        vec![zeta]
                    };
                    (data, vec![pre_points])
                });

                let rounds = round0
                    .into_iter()
                    .chain([round1, round2])
                    .chain(round3)
                    .map(Into::into)
                    .collect();

                // Run the opening argument inside the bracket, lending it the sponge.
                //
                // It seeds its own description from the sponge state reached here.
                transcript.delegate(|challenger| {
                    pcs.open_with_preprocessing(
                        rounds,
                        challenger,
                        preprocessed_data_ref.map(|_| opening_layout.preprocessed),
                    )
                })
            });

            let (opened_values, opening_proof) =
                opening_result.map_err(|source| ProvingError::Pcs {
                    phase: "opening",
                    source,
                })?;

            Ok((
                commitments,
                opened_values,
                opening_proof,
                opening_layout,
                is_random,
                main_next,
                pre_next,
                ood_pow_witness,
            ))
        })();
        let (
            commitments,
            opened_values,
            opening_proof,
            opening_layout,
            is_random,
            main_next,
            pre_next,
            ood_pow_witness,
        ) = match stages {
            Ok(payload) => payload,
            Err(error) => {
                transcript.abort();
                return Err(error);
            }
        };

        // Every described step has now been played.
        transcript.finish();

        let trace_idx = opening_layout.trace;
        let quotient_idx = opening_layout.quotient;
        let trace_local = opened_values[trace_idx][0][0].clone();
        let trace_next = if main_next {
            Some(opened_values[trace_idx][0][1].clone())
        } else {
            None
        };
        let quotient_chunks = opened_values[quotient_idx]
            .iter()
            .map(|v| v[0].clone())
            .collect_vec();
        let random = if is_random {
            Some(opened_values[0][0][0].clone())
        } else {
            None
        };
        let preprocessed = (preprocessed_width > 0).then(|| PreprocessedOpenedValues {
            local: opened_values[opening_layout.preprocessed][0][0].clone(),
            next: pre_next.then(|| opened_values[opening_layout.preprocessed][0][1].clone()),
        });
        let opened_values = OpenedValues {
            trace_local,
            trace_next,
            preprocessed,
            quotient_chunks,
            random,
        };
        let proof = Proof {
            commitments,
            opened_values,
            opening_proof,
            degree_bits: log_ext_degree,
            ood_pow_witness,
        };
        attempt.finish_produced()?;
        Ok(proof)
    })();
    match &result {
        Ok(_) => step.done = true,
        Err(error) => {
            let cause = match error {
                OwnedError::Storage { source, .. } => source.clone(),
                OwnedError::Backend(ProvingError::Pcs { source, .. }) => match source {
                    crate::domain::OpeningProverError::Domain(error) => {
                        Error::OpeningDomain(*error)
                    }
                    crate::domain::OpeningProverError::Inner(error) => Error::Mask(*error),
                },
                _ => Error::Incomplete,
            };
            step.fail(cause);
        }
    }
    result
}
