use crypto_bigint::U256;

// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0
pub mod group_element;
pub mod scalar;

pub use group_element::GroupElement;
pub use scalar::Scalar;

// TODO: validate this

/// The order `q` of the ristretto group
pub const ORDER: U256 =
    U256::from_be_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

/// The modulus `p` of the ristretto group
pub const MODULUS: U256 =
    U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

/// Any Montgomery elliptic curve can be represented as an equation in the following template:
/// $By^{2}=x^{3}+Ax^{2}+x} mod(p)$. For ristretto specifically, $A = 486662$ and $B = 1$, yielding
/// the equation $y^2 = x^3 + 7 mod(p)$.
pub const CURVE_EQUATION_A: U256 =
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000076d06");
pub const CURVE_EQUATION_B: U256 = U256::ONE;
