use std::str::FromStr;

use starknet_core::types::Felt;

pub type ContextId = Felt;

// Context Member ID
pub type ContextIdentity = Felt;

// Context
pub struct Context {
    pub application: Application,
    pub member_count: u32,
}

// Context Application
#[derive(Debug)]
pub struct Application {
    pub id: Felt,  // Represents [u8; 32]
    pub blob: Felt,  // Represents [u8; 32]
    pub size: Felt,
    pub source: Vec<Felt>,  // Represents ApplicationSource
    pub metadata: Vec<Felt>,  // Represents ApplicationMetadata
}

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

pub struct Signed {
    pub payload: Vec<Felt>,
    pub signature: (Felt, Felt),  // (r, s) of the signature
    pub public_key: Felt,
}

pub struct Request {
    pub kind: RequestKind,
    pub signer_id: ContextIdentity,
    pub timestamp_ms: u64,
}

pub enum RequestKind {
    Context(ContextRequest),
}

pub struct ContextRequest {
    pub context_id: ContextId,
    pub kind: ContextRequestKind,
}

pub enum ContextRequestKind {
    Add(ContextIdentity, Application),
}
