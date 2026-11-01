//! Typed geometric admission around the retained actual PCS operations.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use p3_commit::{
    CommitmentOpening, OpenedValues, OpeningRequest, Pcs, PeriodicLdeTable, UnivariateStarkPcs, Val,
};
use p3_field::{ExtensionField, TwoAdicField, coset::TwoAdicMultiplicativeCoset};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    RawTracePoint {
        trace_height: usize,
    },
    NoCommitments,
    NoMatrices {
        batch: usize,
    },
    MatrixCount {
        batch: usize,
        expected: usize,
        got: usize,
    },
    NoPoints {
        batch: usize,
        matrix: usize,
    },
    Height {
        batch: usize,
        matrix: usize,
        height: usize,
    },
    HeightOverflow {
        batch: usize,
        matrix: usize,
    },
    Configuration {
        batch: usize,
    },
    PointInDomain {
        batch: usize,
        matrix: usize,
        point: usize,
        physical_height: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpeningProverError<E> {
    Domain(DomainError),
    Inner(E),
}

#[derive(Debug)]
pub enum OpeningVerifyError<E> {
    Domain(DomainError),
    Inner(E),
}

// Implemented only for the two actual retained PCS families in this crate.
pub(crate) trait Geometry<E, C>: Pcs<E, C>
where
    E: ExtensionField<Val<Self::Domain>>,
{
    fn admit_prover(
        &self,
        rounds: &[OpeningRequest<'_, Self::ProverData, E>],
    ) -> Result<(), DomainError>;
    fn admit_verifier(
        &self,
        rounds: &[CommitmentOpening<E, Self::Commitment, Self::Domain>],
    ) -> Result<(), DomainError>;
}

fn physical_log<F: TwoAdicField>(
    height: usize,
    batch: usize,
    matrix: usize,
) -> Result<usize, DomainError> {
    if !height.is_power_of_two() || height.trailing_zeros() as usize > F::TWO_ADICITY {
        return Err(DomainError::Height {
            batch,
            matrix,
            height,
        });
    }
    Ok(height.trailing_zeros() as usize)
}

fn points<F: TwoAdicField, E: ExtensionField<F>>(
    requested: &[E],
    height: usize,
    batch: usize,
    matrix: usize,
) -> Result<(), DomainError> {
    let log = physical_log::<F>(height, batch, matrix)?;
    if requested.is_empty() {
        return Err(DomainError::NoPoints { batch, matrix });
    }
    // Every retained LDE is physically evaluated on GENERATOR times a subgroup.
    // Logical input shifts and bit-reversed row order do not change this set.
    let target = E::from(F::GENERATOR.exp_power_of_2(log));
    for (point, z) in requested.iter().enumerate() {
        if z.exp_power_of_2(log) == target {
            return Err(DomainError::PointInDomain {
                batch,
                matrix,
                point,
                physical_height: height,
            });
        }
    }
    Ok(())
}

pub(crate) fn matrices<F, E, M>(
    matrices: &[&M],
    requested: &[Vec<E>],
    batch: usize,
) -> Result<(), DomainError>
where
    F: TwoAdicField,
    E: ExtensionField<F>,
    M: Matrix<F>,
{
    if matrices.is_empty() {
        return Err(DomainError::NoMatrices { batch });
    }
    if matrices.len() != requested.len() {
        return Err(DomainError::MatrixCount {
            batch,
            expected: matrices.len(),
            got: requested.len(),
        });
    }
    for (matrix, (data, requested)) in matrices.iter().zip(requested).enumerate() {
        points::<F, E>(requested, data.height(), batch, matrix)?;
    }
    Ok(())
}

pub(crate) fn claims<F, E, Com>(
    rounds: &[CommitmentOpening<E, Com, TwoAdicMultiplicativeCoset<F>>],
    log_blowup: usize,
) -> Result<(), DomainError>
where
    F: TwoAdicField,
    E: ExtensionField<F>,
{
    if rounds.is_empty() {
        return Err(DomainError::NoCommitments);
    }
    for (batch, round) in rounds.iter().enumerate() {
        if round.matrices.is_empty() {
            return Err(DomainError::NoMatrices { batch });
        }
        for (matrix, claim) in round.matrices.iter().enumerate() {
            let log = claim
                .domain
                .log_size()
                .checked_add(log_blowup)
                .ok_or(DomainError::HeightOverflow { batch, matrix })?;
            let shift =
                u32::try_from(log).map_err(|_| DomainError::HeightOverflow { batch, matrix })?;
            let height = 1usize
                .checked_shl(shift)
                .ok_or(DomainError::HeightOverflow { batch, matrix })?;
            physical_log::<F>(height, batch, matrix)?;
            if claim.points.is_empty() {
                return Err(DomainError::NoPoints { batch, matrix });
            }
            let target = E::from(F::GENERATOR.exp_power_of_2(log));
            for (point, opening) in claim.points.iter().enumerate() {
                if opening.point.exp_power_of_2(log) == target {
                    return Err(DomainError::PointInDomain {
                        batch,
                        matrix,
                        point,
                        physical_height: height,
                    });
                }
            }
        }
    }
    Ok(())
}

/// The conditional Clone implementation preserves the retained type's semantics.
/// Constructing this wrapper moves its PCS and does not invoke Clone.
#[derive(Clone, Debug)]
pub struct OpeningChecked<P> {
    inner: P,
}
impl<P> OpeningChecked<P> {
    pub(crate) fn new(inner: P) -> Self {
        Self { inner }
    }
    pub(crate) fn retained(&self) -> &P {
        &self.inner
    }
}

#[allow(
    private_bounds,
    reason = "Geometry is sealed to actual retained PCS implementations"
)]
impl<P, E, C> Pcs<E, C> for OpeningChecked<P>
where
    P: Geometry<E, C>,
    E: ExtensionField<Val<P::Domain>>,
{
    type Domain = P::Domain;
    type Commitment = P::Commitment;
    type ProverData = P::ProverData;
    type Proof = P::Proof;
    type Error = OpeningVerifyError<P::Error>;
    type ProverError = OpeningProverError<P::ProverError>;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        self.inner.natural_domain_for_degree(degree)
    }
    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val<Self::Domain>>)>,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.inner
            .commit(evaluations)
            .map_err(OpeningProverError::Inner)
    }
    fn open(
        &self,
        rounds: Vec<OpeningRequest<'_, Self::ProverData, E>>,
        challenger: &mut C,
    ) -> Result<(OpenedValues<E>, Self::Proof), Self::ProverError> {
        self.inner
            .admit_prover(&rounds)
            .map_err(OpeningProverError::Domain)?;
        self.inner
            .open(rounds, challenger)
            .map_err(OpeningProverError::Inner)
    }
    fn verify(
        &self,
        rounds: Vec<CommitmentOpening<E, Self::Commitment, Self::Domain>>,
        proof: &Self::Proof,
        challenger: &mut C,
    ) -> Result<(), Self::Error> {
        self.inner
            .admit_verifier(&rounds)
            .map_err(OpeningVerifyError::Domain)?;
        self.inner
            .verify(rounds, proof, challenger)
            .map_err(OpeningVerifyError::Inner)
    }
}

#[allow(
    private_bounds,
    reason = "Geometry is sealed to actual retained PCS implementations"
)]
impl<P, E, C> UnivariateStarkPcs<E, C> for OpeningChecked<P>
where
    P: Geometry<E, C> + UnivariateStarkPcs<E, C>,
    E: ExtensionField<Val<P::Domain>>,
{
    type EvaluationsOnDomain<'a> = P::EvaluationsOnDomain<'a>;
    const ZK: bool = P::ZK;
    fn log_max_trace_height(&self) -> usize {
        self.inner.log_max_trace_height()
    }
    fn log_min_trace_height(&self) -> usize {
        self.inner.log_min_trace_height()
    }
    fn commit_preprocessing(
        &self,
        input: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val<Self::Domain>>)>,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.inner
            .commit_preprocessing(input)
            .map_err(OpeningProverError::Inner)
    }
    fn commit_quotient(
        &self,
        domain: Self::Domain,
        input: RowMajorMatrix<Val<Self::Domain>>,
        chunks: usize,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.inner
            .commit_quotient(domain, input, chunks)
            .map_err(OpeningProverError::Inner)
    }
    fn get_quotient_ldes(
        &self,
        input: impl IntoIterator<Item = (Self::Domain, RowMajorMatrix<Val<Self::Domain>>)>,
        chunks: usize,
    ) -> Result<Vec<RowMajorMatrix<Val<Self::Domain>>>, Self::ProverError> {
        self.inner
            .get_quotient_ldes(input, chunks)
            .map_err(OpeningProverError::Inner)
    }
    fn commit_ldes(
        &self,
        input: Vec<RowMajorMatrix<Val<Self::Domain>>>,
    ) -> Result<(Self::Commitment, Self::ProverData), Self::ProverError> {
        self.inner
            .commit_ldes(input)
            .map_err(OpeningProverError::Inner)
    }
    fn get_evaluations_on_domain<'a>(
        &self,
        data: &'a Self::ProverData,
        index: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        self.inner.get_evaluations_on_domain(data, index, domain)
    }
    fn get_evaluations_on_domain_no_random<'a>(
        &self,
        data: &'a Self::ProverData,
        index: usize,
        domain: Self::Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        self.inner
            .get_evaluations_on_domain_no_random(data, index, domain)
    }
    fn open_with_preprocessing(
        &self,
        rounds: Vec<OpeningRequest<'_, Self::ProverData, E>>,
        challenger: &mut C,
        preprocessing: Option<usize>,
    ) -> Result<(OpenedValues<E>, Self::Proof), Self::ProverError> {
        self.inner
            .admit_prover(&rounds)
            .map_err(OpeningProverError::Domain)?;
        self.inner
            .open_with_preprocessing(rounds, challenger, preprocessing)
            .map_err(OpeningProverError::Inner)
    }
    fn verify_with_preprocessing(
        &self,
        rounds: Vec<CommitmentOpening<E, Self::Commitment, Self::Domain>>,
        proof: &Self::Proof,
        challenger: &mut C,
        preprocessing: Option<usize>,
    ) -> Result<(), Self::Error> {
        self.inner
            .admit_verifier(&rounds)
            .map_err(OpeningVerifyError::Domain)?;
        self.inner
            .verify_with_preprocessing(rounds, proof, challenger, preprocessing)
            .map_err(OpeningVerifyError::Inner)
    }
    fn get_opt_randomization_poly_commitment(
        &self,
        domains: impl IntoIterator<Item = Self::Domain>,
    ) -> Result<Option<(Self::Commitment, Self::ProverData)>, Self::ProverError> {
        self.inner
            .get_opt_randomization_poly_commitment(domains)
            .map_err(OpeningProverError::Inner)
    }
    fn build_periodic_lde_table(
        &self,
        columns: &[Vec<Val<Self::Domain>>],
        trace_domain: Self::Domain,
        quotient_domain: Self::Domain,
    ) -> PeriodicLdeTable<Val<Self::Domain>>
    where
        Self::Domain: Clone,
        Val<Self::Domain>: Clone,
    {
        self.inner
            .build_periodic_lde_table(columns, trace_domain, quotient_domain)
    }
}

impl<F, D, I, M, S, E, C> Geometry<E, C> for crate::TwoAdicFriPcs<F, D, I, M, S>
where
    F: TwoAdicField + p3_field::PrimeField64,
    E: ExtensionField<F>,
    D: p3_dft::TwoAdicSubgroupDft<F>,
    I: p3_commit::Mmcs<F, MultiProof: Sync, Error: Sync>,
    M: p3_commit::Mmcs<E>,
    S: crate::storage::MatrixStore<F>,
    C: p3_challenger::FieldChallenger<F>
        + p3_challenger::CanObserve<M::Commitment>
        + p3_challenger::GrindingChallenger<Witness = F>,
{
    fn admit_prover(
        &self,
        rounds: &[OpeningRequest<'_, Self::ProverData, E>],
    ) -> Result<(), DomainError> {
        if rounds.is_empty() {
            return Err(DomainError::NoCommitments);
        }
        for (batch, round) in rounds.iter().enumerate() {
            // The MMCS creates one temporary vector of borrowed matrices.
            let data = self.mmcs.get_matrices(round.prover_data);
            matrices::<F, E, S::Stored>(&data, &round.points, batch)?;
        }
        Ok(())
    }
    fn admit_verifier(
        &self,
        rounds: &[CommitmentOpening<E, Self::Commitment, Self::Domain>],
    ) -> Result<(), DomainError> {
        claims(rounds, self.fri.log_blowup)
    }
}
