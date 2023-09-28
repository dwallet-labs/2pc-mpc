// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

pub mod const_generic_array_serialization;

pub fn flat_map_results<const N: usize, T, E: Clone + fmt::Debug>(results: [Result<T, E>; N]) -> Result<[T; N], E> {
    // Return the first error you encounter, flat-map the array
    if let Some(Err(err)) = results.iter().find(|res| res.is_err()) {
        return Err(err.clone());
    }
    Ok(results.map(|res| res.unwrap()))
}
