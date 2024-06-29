// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use group::{AffineXCoordinate, PrimeGroupElement};

use crate::{Result, sign::verify_signature};

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<const SCALAR_LIMBS: usize, GroupElement: PrimeGroupElement<SCALAR_LIMBS>> {
    pub(super) message: GroupElement::Scalar,
    pub(super) public_key: GroupElement,
}

impl<
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS>,
    > Party<SCALAR_LIMBS, GroupElement>
{
    pub fn verify_signature(
        self,
        nonce_x_coordinate: GroupElement::Scalar,
        signature_s: GroupElement::Scalar,
    ) -> Result<()> {
        verify_signature(
            nonce_x_coordinate, // = r
            signature_s,        // = s
            self.message,       // = m
            self.public_key,    // = X
        )?;

        Ok(())
    }

    pub fn new(
        message: GroupElement::Scalar,
        public_key: GroupElement::Value,
        group_public_parameters: &group::PublicParameters<GroupElement>,
    ) -> Result<Self> {
        let public_key = GroupElement::new(public_key, group_public_parameters)?;
        Ok(Self {
            message,
            public_key,
        })
    }
}
