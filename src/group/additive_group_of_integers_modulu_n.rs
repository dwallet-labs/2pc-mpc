// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

// Crypto-bigint has two structures we can work with for modular arithmetics;
// 1. DynResidue - uses Montgomery and works for odd moduli only, used in `odd_modulu`
// 2. Wrapping<Uint<>> - works for moduli which is a multiple of the LIMB size 2^64, and is much
//    more efficient - used in `power_of_two_modulu`.
//
// For groups like the Paillier plaintext space, 1 is more appropriate.
// For groups that should behave like the integers group $Z$ but bounded by some upper bound, 2. is
// more appropriate.

pub mod odd_moduli;
pub mod power_of_two_moduli;
