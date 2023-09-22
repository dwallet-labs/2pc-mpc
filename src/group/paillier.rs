// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::modular::runtime_mod::DynResidue;
use tiresias::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

use crate::group::multiplicative_group_of_integers_modulu_n;

pub type PlaintextGroupElement = DynResidue<{ LargeBiPrimeSizedNumber::LIMBS }>;

pub type CiphertextGroupElement =
    multiplicative_group_of_integers_modulu_n::GroupElement<{ PaillierModulusSizedNumber::LIMBS }>;

pub type RandomnessGroupElement =
    multiplicative_group_of_integers_modulu_n::GroupElement<{ LargeBiPrimeSizedNumber::LIMBS }>;
