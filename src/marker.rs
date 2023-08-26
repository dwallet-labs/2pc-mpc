// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::{cmp::Ordering, fmt, marker::PhantomData};

use serde::{Deserialize, Serialize};

/// Zero-sized marker type denoting choice over some generic parameter T
#[derive(Serialize, Deserialize)]
pub struct Marker<T>(PhantomData<fn(T)>);

impl<T> Default for Marker<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> Marker<T> {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T> Clone for Marker<T> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<T> fmt::Debug for Marker<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Marker<_>")
    }
}

impl<T> PartialEq for Marker<T> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<T> Eq for Marker<T> {}

impl<T> PartialOrd for Marker<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Marker<T> {
    fn cmp(&self, _other: &Self) -> Ordering {
        Ordering::Equal
    }
}
