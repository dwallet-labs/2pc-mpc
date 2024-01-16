// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub use language::{
    committed_linear_evaluation, committment_of_discrete_log,
    discrete_log_ratio_of_committed_values, encryption_of_discrete_log, encryption_of_tuple,
    knowledge_of_decommitment, knowledge_of_discrete_log, Language,
};
pub use proof::Proof;

pub mod enhanced {
    pub use super::{language::enhanced::*, proof::enhanced::*};

    #[cfg(any(test, feature = "benchmarking"))]
    pub(crate) mod tests {
        pub use super::super::{language::enhanced::tests::*, proof::enhanced::tests::*};
    }
}

pub mod aggregation;
pub mod language;
pub mod proof;
