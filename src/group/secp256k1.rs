// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

pub mod group_element;
pub mod scalar;

use crypto_bigint::U256;
pub use group_element::GroupElement;
use k256::{elliptic_curve::Curve, Secp256k1};
pub use scalar::Scalar;

pub const SCALAR_LIMBS: usize = U256::LIMBS;

/// The order `q` of the secp256k1 group
pub const ORDER: U256 = <Secp256k1 as Curve>::ORDER;
/// The modulus `p` of the secp256k1 group
pub const MODULUS: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// Any Weierstrass elliptic curve can be represented as an equation in the following template: $y^2
/// = x^3 + ax^ + b mod(p)$. For secp256k1 specifically, $a = 0$ and $b = 7$, yielding the equation
/// $y^2 = x^3 + 7 mod(p)$.
pub const CURVE_EQUATION_A: U256 = U256::ZERO;
pub const CURVE_EQUATION_B: U256 =
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000007");
