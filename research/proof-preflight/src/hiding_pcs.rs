#![forbid(unsafe_code)]
// The source pinned verifier retains its original boolean expression.
#![allow(clippy::nonminimal_bool)]
include!("../../storage-pcs/backend/src/hiding_pcs.rs");

/// Pure view of the retained masking check. No prover data is opened.
impl<Val, Dft, InputMmcs, FriMmcs, R, Store> HidingFriPcs<Val, Dft, InputMmcs, FriMmcs, R, Store> {
    pub fn masking_preflight<Challenge>(
        &self,
        mask_height: usize,
        num_points: usize,
    ) -> Result<crate::preflight::MaskBudget, HidingFriProverError>
    where
        Val: p3_field::Field,
        Challenge: ExtensionField<Val>,
    {
        self.check_hiding_budget(mask_height, Challenge::DIMENSION, num_points)?;
        Ok(crate::preflight::MaskBudget {
            extension: Challenge::DIMENSION,
            random_columns: self.num_random_codewords,
            queries: self.inner.fri.num_queries,
            points: num_points.max(1),
            minimum_height: self
                .hiding_budget(Challenge::DIMENSION, num_points)
                .ok_or(HidingFriProverError::BudgetOverflow)?,
        })
    }

    pub(crate) fn resource_parameters(&self) -> crate::preflight::Parameters {
        crate::preflight::Parameters {
            random_columns: self.num_random_codewords,
            queries: self.inner.fri.num_queries,
            log_blowup: self.inner.fri.log_blowup,
            log_final_poly_len: self.inner.fri.log_final_poly_len,
            max_log_arity: self.inner.fri.max_log_arity,
            grinding: [
                self.inner.fri.batch_proof_of_work_bits,
                self.inner.fri.commit_proof_of_work_bits,
                self.inner.fri.query_proof_of_work_bits,
            ],
        }
    }

    pub fn resource_plan<Challenge, A>(
        &self,
        air: &A,
        request: crate::preflight::Request,
    ) -> Result<crate::preflight::ResourcePlan, crate::preflight::Refusal>
    where
        Val: TwoAdicField + PrimeField64,
        Dft: TwoAdicSubgroupDft<Val>,
        InputMmcs: Mmcs<Val>,
        FriMmcs: Mmcs<Challenge>,
        R: CryptoRng + Send + Sync,
        Store: MatrixStore<Val>,
        Challenge: TwoAdicField + ExtensionField<Val>,
        A: p3_air::Air<p3_air::symbolic::SymbolicAirBuilder<Val>>,
    {
        crate::preflight::resource_plan::<Val, Dft, InputMmcs, FriMmcs, R, Store, Challenge, A>(
            self, air, request,
        )
    }
}
