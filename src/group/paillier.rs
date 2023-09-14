// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::group::{
    additive_group_of_integers_modulu_n, multiplicative_group_of_integers_modulu_n,
};

pub type CiphertextGroupElement =
    multiplicative_group_of_integers_modulu_n::GroupElement<{ PaillierModulusSizedNumber::LIMBS }>;

pub type RandomnessGroupElement =
    multiplicative_group_of_integers_modulu_n::GroupElement<{ LargeBiPrimeSizedNumber::LIMBS }>;

pub type MessageGroupElement =
    additive_group_of_integers_modulu_n::GroupElement<{ LargeBiPrimeSizedNumber::LIMBS }>;
