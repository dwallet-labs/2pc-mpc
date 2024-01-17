// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::fmt;

pub mod const_generic_array_serialization;

pub trait FlatMapResults<T, E: fmt::Debug>: AsRef<[Result<T, E>]> {
    type Output: AsRef<[T]>;

    fn flat_map_results(self) -> Result<Self::Output, E>;
}

impl<const N: usize, T, E: fmt::Debug> FlatMapResults<T, E> for [Result<T, E>; N] {
    type Output = [T; N];

    fn flat_map_results(self) -> Result<Self::Output, E> {
        let res: Result<Vec<T>, E> = self.into_iter().collect();

        // We know the vector is of the right size, so this is safe to unwrap
        res.map(|vec| vec.try_into().ok().unwrap())
    }
}
