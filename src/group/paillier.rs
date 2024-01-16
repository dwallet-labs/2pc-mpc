// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::group::{
    additive_group_of_integers_modulu_n::odd_moduli, multiplicative_group_of_integers_modulu_n,
};

pub const PLAINTEXT_SPACE_SCALAR_LIMBS: usize = LargeBiPrimeSizedNumber::LIMBS;
pub const RANDOMNESS_SPACE_SCALAR_LIMBS: usize = LargeBiPrimeSizedNumber::LIMBS;

pub const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize = PaillierModulusSizedNumber::LIMBS;

pub type PlaintextSpaceGroupElement = odd_moduli::GroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>;
pub type RandomnessSpaceGroupElement =
    multiplicative_group_of_integers_modulu_n::GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>;

pub type CiphertextSpaceGroupElement =
    multiplicative_group_of_integers_modulu_n::GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>;

pub type PlaintextSpacePublicParameters =
    odd_moduli::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS>;

pub type RandomnessSpacePublicParameters =
    multiplicative_group_of_integers_modulu_n::PublicParameters<RANDOMNESS_SPACE_SCALAR_LIMBS>;

pub type CiphertextSpacePublicParameters =
    multiplicative_group_of_integers_modulu_n::PublicParameters<CIPHERTEXT_SPACE_SCALAR_LIMBS>;
