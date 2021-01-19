use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Policies(pub(crate) BTreeMap<String, Vec<Vec<String>>>);

impl Policies {
    pub fn new() -> Policies {
        Policies(BTreeMap::new())
    }
}
