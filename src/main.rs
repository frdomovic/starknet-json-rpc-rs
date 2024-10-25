use bs58;
use hex;
use starknet::accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet::core::chain_id;
use starknet::core::crypto::ExtendedSignature;
use starknet::core::types::{
    BlockId, BlockTag, BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1, Call, CallType, ComputationResources, ContractClass, EntryPointType, Felt, FunctionCall, FunctionInvocation, InvokeTransactionV1
};
use starknet::core::utils::get_selector_from_name;
use starknet::providers::sequencer::models::InvokeFunctionTransaction;
use starknet::signers::{LocalWallet, SigningKey};
use starknet_crypto::{poseidon_hash_many, Signature};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};
use core::str;
use std::collections::BTreeMap;
use std::str::Bytes;
use std::{borrow::Cow, str::FromStr};
use thiserror::Error;
use types::{ContextId, ContextIdentity};
// use starknet_core::codec::{ArrayTrait, Encode};
use starknet::core::codec::Encode;

use serde::{Serialize, Deserialize};
mod types;

#[derive(Debug)]
pub struct NetworkConfig {
    pub rpc_url: Url,
    pub account_id: String,
    pub access_key: String,
}

#[derive(Debug)]
pub struct StarknetConfig<'a> {
    pub networks: BTreeMap<Cow<'a, str>, NetworkConfig>,
}

#[derive(Debug)]
struct Network {
    client: JsonRpcClient<HttpTransport>,
    account_id: String,
    secret_key: String,
}

#[derive(Debug)]
pub struct StarknetTransport<'a> {
    networks: BTreeMap<Cow<'a, str>, Network>,
}

impl<'a> StarknetTransport<'a> {
    #[must_use]
    pub fn new(config: &StarknetConfig<'a>) -> Self {
        let mut networks = BTreeMap::new();

        for (network_id, network_config) in &config.networks {
            let client = JsonRpcClient::new(HttpTransport::new(network_config.rpc_url.clone()));
            let _ignored = networks.insert(
                network_id.clone(),
                Network {
                    client,
                    account_id: network_config.account_id.clone(),
                    secret_key: network_config.access_key.clone(),
                },
            );
        }

        Self { networks }
    }
}

fn compute_transaction_hash(
    sender_address: Felt,
    contract_address: Felt,
    entry_point_selector: Felt,
    calldata: Vec<Felt>,
) -> Felt {
    let elements: Vec<Felt> = vec![sender_address, contract_address, entry_point_selector]
        .into_iter()
        .chain(calldata.into_iter())
        .collect();

    poseidon_hash_many(&elements)
}

async fn sign_transaction(hash: &Felt, secret_key: &Felt) -> Result<ExtendedSignature, StarknetError> {
    let signature = starknet::core::crypto::ecdsa_sign(secret_key, hash).unwrap();
    Ok(signature)
    // match signature {
    //     Ok(result) => Ok(result.into()),
    //     Err(_) => Err(StarknetError::InvalidResponse {
    //         operation: ErrorOperation::Query,
    //     }),
    // }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StarknetError {
    #[error("unknown network `{0}`")]
    UnknownNetwork(String),
    #[error("invalid response from RPC while {operation}")]
    InvalidResponse { operation: ErrorOperation },
    #[error("invalid contract ID `{0}`")]
    InvalidContractId(String),
    #[error("access key does not have permission to call contract `{0}`")]
    NotPermittedToCallContract(String),
    #[error(
        "access key does not have permission to call method `{method}` on contract {contract}"
    )]
    NotPermittedToCallMethod { contract: String, method: String },
    #[error("transaction timed out")]
    TransactionTimeout,
    #[error("error while {operation}: {reason}")]
    Custom {
        operation: ErrorOperation,
        reason: String,
    },
}

// fn application_to_felt_vec(application: &Application) -> Vec<Felt> {
//     let mut felt_vec = Vec::new();
    
//     // Add single fields
//     felt_vec.push(application.id);
//     felt_vec.push(application.blob);
//     felt_vec.push(application.size);
    
//     // Add collection fields (source and metadata)
//     felt_vec.extend(application.source.iter().cloned());
//     felt_vec.extend(application.metadata.iter().cloned());
    
//     felt_vec
// }


#[derive(Copy, Clone, Debug, Error)]
#[non_exhaustive]
pub enum ErrorOperation {
    #[error("querying contract")]
    Query,
    #[error("mutating contract")]
    Mutate,
    #[error("fetching account")]
    FetchAccount,
}

impl Network {
    async fn query(
        &self,
        contract_id: &str,
        method: &str,
        args: Vec<u8>,
    ) -> Result<Vec<Felt>, StarknetError> {
        let contract_id = Felt::from_str(contract_id)
            .unwrap_or_else(|_| panic!("Failed to convert contract id to felt type"));

        let entry_point_selector = get_selector_from_name(method)
            .unwrap_or_else(|_| panic!("Failed to convert method name to entry point selector"));

        let calldata: Vec<Felt> = if args.is_empty() {
            vec![]
        } else {
            args.chunks(32)
                .map(|chunk| {
                    let mut padded_chunk = [0u8; 32];
                    for (i, byte) in chunk.iter().enumerate() {
                        padded_chunk[i] = *byte;
                    }
                    Felt::from_bytes_be(&padded_chunk)
                })
                .collect()
        };

        let function_call = FunctionCall {
            contract_address: contract_id,
            entry_point_selector,
            calldata,
        };

        let response = self
            .client
            .call(&function_call, BlockId::Tag(BlockTag::Latest))
            .await;

        match response {
            Ok(result) => Ok(result),
            Err(_) => Err(StarknetError::InvalidResponse {
                operation: ErrorOperation::Query,
            }),
        }
    }

    async fn mutate(&self, contract_id: &str, method: &str, args: Vec<u8>) {
        let sender_address: Felt = Felt::from_str(&self.account_id)
            .unwrap_or_else(|_| panic!("Failed to convert sender address to felt type"));
        let secret_key: Felt = Felt::from_str(self.secret_key.as_str())
            .unwrap_or_else(|_| panic!("Failed to convert sender address to felt type"));

        let nonce = self
            .get_nonce(self.account_id.as_str())
            .await
            .unwrap_or_else(|_| panic!("Failed to get nonce"));

        let contract_id = Felt::from_str(contract_id)
            .unwrap_or_else(|_| panic!("Failed to convert contract id to felt type"));

        // let response2 = self
        //     .client
        //     .get_class_at(BlockId::Tag(BlockTag::Latest), contract_id).await;
        // match response2 {
        //     Ok(class) => {
        //         let compressed_class = match class {
        //             ContractClass::Legacy(legacy_class) => legacy_class,
        //             _ => panic!("Failed to compress contract class"),
        //         };
        //         let legacy_contract = ContractClass::Legacy(compressed_class);

        //         // Now you can use `legacy_contract` as needed
        //         println!("Successfully retrieved legacy contract: {:?}", legacy_contract);

        //         // Optionally write the legacy contract to a file if needed
        //         let file = File::create("abi.json");
        //         match file {
        //             Ok(mut file) => {
        //                 if let Err(e) = to_writer(&file, &legacy_contract) {
        //                     println!("Failed to write ABI to file: {:?}", e);
        //                 } else {
        //                     println!("ABI successfully written to abi.json");
        //                 }
        //             }
        //             Err(e) => println!("Failed to create file: {:?}", e),
        //         }
        //     },
        //     Err(e) => println!("Failed to get class at contract: {:?}", e),
        // }

        let entry_point_selector = get_selector_from_name(method)
            .unwrap_or_else(|_| panic!("Failed to convert method name to entry point selector"));




        let calldata: Vec<Felt> = if args.is_empty() {
            vec![]
        } else {
            args.chunks(32)
                .map(|chunk| {
                    let mut padded_chunk = [0u8; 32];
                    for (i, byte) in chunk.iter().enumerate() {
                        padded_chunk[i] = *byte;
                    }
                    Felt::from_bytes_be(&padded_chunk)
                })
                .collect()
        };

        let transaction_hash = compute_transaction_hash(
            sender_address,
            contract_id,
            entry_point_selector,
            calldata.clone(),
        );

        let signature = sign_transaction(&transaction_hash, &secret_key)
            .await
            .unwrap();

        let signature_vec: Vec<Felt> = vec![
            Felt::from_str("0x0").unwrap(),
            Felt::from_str("0x0").unwrap(),
        ];

        // let application = Application {
        //     id: Felt::from_raw(6382179),
        //     blob: 7092165981550440290i64.into(),
        //     size: 0.into(),
        //     source: [7161124082558530159i64.into()].to_vec(),
        //     metadata: [1835365473.into()].to_vec(),
        // };

        // let calldata = application_to_felt_vec(&application);

        // let invoke_transaction_v1 = BroadcastedInvokeTransactionV1 {
        //     sender_address,
        //     calldata,

        //     max_fee: Felt::from(304139049569u64),
        //     signature: signature_vec,
        //     nonce,
        //     is_query: false,
        // };
        // let broadcasted_transaction = BroadcastedInvokeTransaction::V1(invoke_transaction_v1);
        // let response = self
        //     .client
        //     .add_invoke_transaction(&broadcasted_transaction)
        //     .await;
        // match response {
        //     Ok(result) => {
        //         println!("Transaction successful: {:?}", result);
        //     }
        //     Err(err) => {
        //         eprintln!("Error adding invoke transaction: {:?}", err);
        //     }
        // }
    }

    async fn get_nonce(&self, contract_id: &str) -> Result<Felt, StarknetError> {
        let contract_id = Felt::from_str(contract_id)
            .unwrap_or_else(|_| panic!("Failed to convert contract id to felt type"));

        let response = self
            .client
            .get_nonce(BlockId::Tag(BlockTag::Latest), contract_id)
            .await;

        match response {
            Ok(nonce) => Ok(nonce),
            Err(_) => Err(StarknetError::InvalidResponse {
                operation: ErrorOperation::FetchAccount,
            }),
        }
    }
}

#[tokio::main]
async fn main() {
    test1().await;
    test2().await;
}

async fn test1() {
    let rpc_url = Url::parse("https://free-rpc.nethermind.io/sepolia-juno/")
        .expect("Invalid Starknet RPC URL");

    let network_config = NetworkConfig {
        rpc_url,
        account_id: "0x050A17C9A206e1320b3b885e5E4C53ddC249f17059681A556366c3bFa653694f"
            .to_string(),
        access_key: "0x01ef5007af6ab4e514d4d559853c5435bd17ab03a1d5b57bc10b5d06fbda3142"
            .to_string(),
    };

    let mut network_map = BTreeMap::new();
    network_map.insert(Cow::Borrowed("sepolia"), network_config);

    let starknet_config = StarknetConfig {
        networks: network_map,
    };

    let starknet_transport = StarknetTransport::new(&starknet_config);
    let network = starknet_transport
        .networks
        .get("sepolia")
        .expect("Failed to get the network configuration");

    let contract_id = "0x008f4a3c215d4f5b2c6c2cf58ad4cd5f8ea55be51c816b20a81f1940ab7724b4";
    let acc = "9gmAGcQ4dyLgk7WNzPA7AqsPh7igXiEdKRLgSGVUMEeZ";

    let method = "application";

    let account_bytes = bs58::decode(acc)
        .into_vec()
        .expect("Failed to decode base58 string");

    let args: Vec<u8> = account_bytes;

    match network.query(contract_id, method, args.clone()).await {
        Ok(result) => {
            println!("{:?}", result);
        }
        Err(e) => {
            println!("Query failed with error: {:?}", e);
        }
    }
}

async fn test2() {
    let rpc_url = Url::parse("https://free-rpc.nethermind.io/sepolia-juno/")
        .expect("Invalid Starknet RPC URL");

    let network_config = NetworkConfig {
        rpc_url,
        account_id: "0x050A17C9A206e1320b3b885e5E4C53ddC249f17059681A556366c3bFa653694f"
            .to_string(),
        access_key: "0x01ef5007af6ab4e514d4d559853c5435bd17ab03a1d5b57bc10b5d06fbda3142"
            .to_string(),
    };

    let mut network_map = BTreeMap::new();
    network_map.insert(Cow::Borrowed("sepolia"), network_config);

    let starknet_config = StarknetConfig {
        networks: network_map,
    };

    let starknet_transport = StarknetTransport::new(&starknet_config);
    let network = starknet_transport
        .networks
        .get("sepolia")
        .expect("Failed to get the network configuration");

    let contract_id = "0x008f4a3c215d4f5b2c6c2cf58ad4cd5f8ea55be51c816b20a81f1940ab7724b4";
    let acc = "9gmAGcQ4dyLgk7WNzPA7AqsPh7igXiEdKRLgSGVUMEeZ";

    let method = "mutate";

    // let context_id = "0x1f446d0850b5779b50c1e30ead2e5609614e94fe5d5598aa5459ee73c4f3604".into();
    // let author_id = "0x660ad6d4b87091520b5505433340abdd181a00856443010fa799f945d2dd5da".into();
    // let account_bytes = bs58::decode(acc)
    //     .into_vec()
    //     .expect("Failed to decode base58 string");

    let args: Vec<u8> = vec![];

    // let context_id: ContextId =
    //     Felt::from_str("0x1f446d0850b5779b50c1e30ead2e5609614e94fe5d5598aa5459ee73c4f3604")
    //         .unwrap();
    // let author_id: ContextIdentity =
    //     Felt::from_str("0x660ad6d4b87091520b5505433340abdd181a00856443010fa799f945d2dd5da")
    //         .unwrap();

    let alice_key = starknet::signers::SigningKey::from_random();
    let alice_key_felt = starknet::signers::SigningKey::secret_scalar(&alice_key);
    let alice_public_key = alice_key.verifying_key();
    let alice_public_key_felt = alice_public_key.scalar();
    println!("Alice Signing key: {:?}", alice_key);
    println!("Alice Public key: {:?}", alice_public_key);

    let context_key = starknet::signers::SigningKey::from_random();
    let context_public_key = context_key.verifying_key();
    let context_public_key_felt = context_public_key.scalar();
    println!("Context Signing key: {:?}", context_key);
    println!("Context Public key: {:?}", context_public_key);

    let application = Application {
        id: 6382179.into(),
        blob: 7092165981550440290i64.into(),
        size: 0,
        source: "https://github.com/calimero-network/core".as_bytes().to_vec(),
        metadata: "some metadata".as_bytes().to_vec(),
    };

    let request = Request {
        signer_id: alice_public_key_felt,
        nonce: 0,
        kind: RequestKind::Context(
          ContextRequest {
            context_id: context_public_key_felt,
            kind: ContextRequestKind::Add(
              context_public_key_felt,
              application.clone()
            ),
        }),
    };

    // let mut serialized = Vec::new();
    // request.serialize(&mut serialized);
    let mut serialized = vec![];
    let _ = request.encode(&mut serialized);
    println!("Serialized: {:?}", serialized);

    let hash = poseidon_hash_many(&serialized);
    println!("Hash: {:?}", hash);

    let signature = alice_key.sign(&hash).unwrap();
    println!("Signature: {:?}", signature);

    let signed_request = Signed {
        payload: serialized,
        signature: vec![signature.r, signature.s],
    };

    println!("Signed Request: {:?}", signed_request);

    let mut signed_request_serialized = vec![];
    let _ = signed_request.encode(&mut signed_request_serialized);

    //Call the contract
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse("https://starknet-sepolia.public.blastapi.io/rpc/v0_7").unwrap(),
    ));

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        Felt::from_hex("0x3466a2196c72a94edd80c49baaad89c3cd71815038c31e1d3c94337ad97406d").unwrap(),
    ));
    let address = Felt::from_hex("0x008f4a3c215d4f5b2c6c2cf58ad4cd5f8ea55be51c816b20a81f1940ab7724b4").unwrap();
    let tst_token_address =
        Felt::from_hex("07394cbe418daa16e42b87ba67372d4ab4a5df0b05c6e554d158458ce245bc10").unwrap();

    let mut account = SingleOwnerAccount::new(
        provider,
        signer,
        address,
        chain_id::SEPOLIA,
        ExecutionEncoding::New,
    );

    // `SingleOwnerAccount` defaults to checking nonce and estimating fees against the latest
    // block. Optionally change the target block to pending with the following line:
    account.set_block_id(BlockId::Tag(BlockTag::Pending));

    let result = account
        .execute_v3(vec![Call {
            to: Felt::from_str(contract_id).unwrap(),
            selector: Felt::from_str("0x33f8af2c6d5b2376345a3c43ad230b0741fb5694c7064741c1927142bbd442a").unwrap(),
            calldata: signed_request_serialized,
        }])
        .send()
        .await
        .unwrap();

    println!("{:?}", result);


    // network.mutate(contract_id, method, signed_request).await;
}

#[derive(Debug, Encode)]
pub struct Signed {
    payload: Vec<Felt>,
    signature: Vec<Felt>,
}

#[derive(Encode)]
pub struct Request {
    kind: RequestKind,
    signer_id: ContextIdentity,
    nonce: u64,
}

#[derive(Debug, Serialize, Deserialize, Encode)]
pub enum RequestKind {
    Context(ContextRequest),
}

#[derive(Debug, Serialize, Deserialize, Encode)]
pub struct ContextRequest {
    pub context_id: ContextId,
    pub kind: ContextRequestKind,
}

#[derive(Debug, Serialize, Deserialize, Encode)]
pub enum ContextRequestKind {
    Add(ContextIdentity, Application),
    // UpdateApplication(Application),
    // AddMembers(Vec<ContextIdentity>),
    // RemoveMembers(Vec<ContextIdentity>),
    // Grant(Vec<(ContextIdentity, Capability)>),
    // Revoke(Vec<(ContextIdentity, Capability)>),
}

pub struct Context {
  pub application: Application,
  pub member_count: u32,
}

// Context Application
#[derive(Debug, Serialize, Deserialize, Clone, Encode)]
pub struct Application {
  pub id: Felt,  // Represents [u8; 32]
  pub blob: Felt,  // Represents [u8; 32]
  pub size: u64,
  pub source: Vec<u8>,  // Represents ApplicationSource
  pub metadata: Vec<u8>  // Represents ApplicationMetadata
}

// impl<T: Serialize> Signed<T> {
//   pub fn new<R, F>(payload: &T, sign: F) -> Result<Self, ConfigError<R::Error>>
//   where
//       R: IntoResult<Signature>,
//       F: FnOnce(&[u8]) -> R,
//   {
//       let payload = serde_json::to_vec(&payload)?.into_boxed_slice();

//       let signature = sign(&payload)
//           .into_result()
//           .map_err(ConfigError::DerivationError)?;

//       Ok(Self {
//           payload: Repr::new(payload),
//           signature: Repr::new(signature),
//       })
//   }
// }

// pub trait IntoResult<T> {
//   type Error;

//   fn into_result(self) -> Result<T, Self::Error>;
// }

// impl<T> IntoResult<T> for T {
//   type Error = Infallible;

//   fn into_result(self) -> Result<T, Self::Error> {
//       Ok(self)
//   }
// }

// impl<T, E> IntoResult<T> for Result<T, E> {
//   type Error = E;

//   fn into_result(self) -> Result<T, Self::Error> {
//       self
//   }
// }

// impl<'a, T: Deserialize<'a>> Signed<T> {
//   pub fn parse<R, F>(&'a self, f: F) -> Result<T, ConfigError<R::Error>>
//   where
//       R: IntoResult<SignerId>,
//       F: FnOnce(&T) -> R,
//   {
//       let parsed = serde_json::from_slice(&self.payload)?;

//       let bytes = f(&parsed)
//           .into_result()
//           .map_err(ConfigError::DerivationError)?;

//       let key = bytes
//           .rt::<VerifyingKey>()
//           .map_err(ConfigError::VerificationKeyParseError)?;

//       key.verify(&self.payload, &self.signature)
//           .map_or(Err(ConfigError::InvalidSignature), |()| Ok(parsed))
//   }
// }


// #[serde_as]
// #[derive(Serialize, Deserialize, Debug)]
// pub struct Application<'a> {
//     pub id: Felt,
//     pub blob: Felt,
//     pub size: u64,
//     pub source: ApplicationSource<'a>,
//     pub metadata: ApplicationMetadata<'a>,
// }

// pub struct ApplicationMetadata<'a>(#[serde(borrow)] pub Repr<Cow<'a, [u8]>>);

// pub struct ApplicationSource<'a>(#[serde(borrow)] pub Cow<'a, str>);

// impl ApplicationSource<'_> {
//     #[must_use]
//     pub fn to_owned(self) -> ApplicationSource<'static> {
//         ApplicationSource(Cow::Owned(self.0.into_owned()))
//     }
// }

//CONVERT FELT TO STRING / DECIMAL - DOESN'T WORK FOR JSON STRINGS
// fn felt_to_short_string(value: Felt) -> String {
//     let mut chars = Vec::new();

//     let mut value_bytes: Vec<u8> = value.to_bytes_be().to_vec();

//     while value_bytes.first() == Some(&0) {
//         value_bytes.remove(0);
//     }

//     let felt_value = value.to_string();
//     if felt_value.starts_with("0x") && felt_value.len() >= 40 {
//         return format!("Contract Address: {}", felt_value);
//     }

//     let mut is_string = true;

//     for &byte in &value_bytes {
//         if byte >= 0x20 && byte <= 0x7E {
//             if let Some(character) = std::char::from_u32(byte as u32) {
//                 chars.push(character);
//             }
//         } else {
//             is_string = false;
//             break;
//         }
//     }

//     if is_string {
//         let result_string: String = chars.into_iter().collect();
//         return result_string;
//     } else {
//         format!("Decimal: {}, Hex: 0x{:x}", value.to_string(), value)
//     }
// }

