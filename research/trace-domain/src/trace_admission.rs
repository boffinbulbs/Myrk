//! Raw trace-domain refusal before any opening values are computed.
#![forbid(unsafe_code)]
use crate::domain::DomainError;
use p3_commit::PolynomialSpace;
use p3_field::{ExtensionField, TwoAdicField, coset::TwoAdicMultiplicativeCoset};

pub(crate) fn admit_raw<F: TwoAdicField, E: ExtensionField<F>>(
    raw_domain: TwoAdicMultiplicativeCoset<F>,
    point: E,
) -> Result<(), DomainError> {
    if raw_domain.vanishing_poly_at_point(point) == E::ZERO {
        return Err(DomainError::RawTracePoint {
            trace_height: raw_domain.size(),
        });
    }
    Ok(())
}
