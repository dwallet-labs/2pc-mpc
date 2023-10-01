// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: Apache-2.0

use std::{array, fmt};

pub mod const_generic_array_serialization;

pub fn flat_map_results<const N: usize, T, E: fmt::Debug>(
    results: [Result<T, E>; N],
) -> Result<[T; N], E> {
    let res: Result<Vec<T>, E> = results.into_iter().collect();

    // We know the iterator is of the right size, so this is safe to unwrap
    res.map(|vec| {
        let mut iter = vec.into_iter();
        array::from_fn(|_| iter.next().unwrap())
    })
}
