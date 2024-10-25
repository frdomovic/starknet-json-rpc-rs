use std::str::FromStr;

use serde::{Serialize, Deserialize};
use starknet::core::types::Felt;

pub type ContextId = Felt;

// Context Member ID
pub type ContextIdentity = Felt;

// Context

// Context Config
pub struct Config {
    pub validity_threshold_ms: u64,
}

// #[derive(Drop, Serde)]
// pub struct ContextDetails {
//     pub context_id: felt252,  // Represents [u8; 32]
//     pub application: Application,
//     pub member_count: u32,
//     pub members: Array<ContextIdentity>,
// }

// Context Capabilities
pub enum Capability {
    ManageApplication,
    ManageMembers,
}

// Convert Capability to felt252
impl Into<Felt> for Capability {
    fn into(self: Capability) -> Felt {
        match self {
            Capability::ManageApplication => Felt::from_str("0x0").unwrap(),
            Capability::ManageMembers => Felt::from_str("0x0").unwrap(),
        }
    }
}
