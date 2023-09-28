// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::group::{additive_group_of_integers_modulu_n::odd_moduli, multiplicative_group_of_integers_modulu_n};
pub type PlaintextGroupElement = odd_moduli::GroupElement<{ LargeBiPrimeSizedNumber::LIMBS }>;
pub type RandomnessGroupElement = multiplicative_group_of_integers_modulu_n::GroupElement<{ LargeBiPrimeSizedNumber::LIMBS }>;

pub type CiphertextGroupElement = multiplicative_group_of_integers_modulu_n::GroupElement<{ PaillierModulusSizedNumber::LIMBS }>;

pub type PlaintextPublicParameters = odd_moduli::PublicParameters<{ LargeBiPrimeSizedNumber::LIMBS }>;

pub type RandomnessPublicParameters = multiplicative_group_of_integers_modulu_n::PublicParameters<{ LargeBiPrimeSizedNumber::LIMBS }>;

pub type CiphertextPublicParameters =
    multiplicative_group_of_integers_modulu_n::PublicParameters<{ PaillierModulusSizedNumber::LIMBS }>;
