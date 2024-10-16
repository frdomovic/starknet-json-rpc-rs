use hex;
use starknet_core::types::{
    BlockId, BlockTag, BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1, Felt,
    FunctionCall, InvokeTransactionV1,
};
use starknet_core::utils::get_selector_from_name;
use starknet_crypto::{poseidon_hash_many, Signature};
use starknet_providers::jsonrpc::HttpTransport;
use starknet_providers::{JsonRpcClient, Provider, Url};
use std::collections::BTreeMap;
use std::{borrow::Cow, str::FromStr};
use thiserror::Error;

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

async fn sign_transaction(hash: &Felt, secret_key: &Felt) -> Result<Signature, StarknetError> {
    let signature = starknet_core::crypto::ecdsa_sign(secret_key, hash);
    match signature {
        Ok(result) => Ok(result.into()),
        Err(_) => Err(StarknetError::InvalidResponse {
            operation: ErrorOperation::Query,
        }),
    }
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
        let sender_address: Felt = Felt::from_str(self.account_id.as_str())
            .unwrap_or_else(|_| panic!("Failed to convert sender address to felt type"));
        let secret_key: Felt = Felt::from_str(self.secret_key.as_str())
            .unwrap_or_else(|_| panic!("Failed to convert sender address to felt type"));

        let nonce = self
            .get_nonce(self.account_id.as_str())
            .await
            .unwrap_or_else(|_| panic!("Failed to get nonce"));

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

        let transaction_hash = compute_transaction_hash(
            sender_address,
            contract_id,
            entry_point_selector,
            calldata.clone(),
        );

        let signature = sign_transaction(&transaction_hash, &secret_key)
            .await
            .unwrap();

        let signature_vec: Vec<Felt> = vec![signature.r, signature.s];

        let invoke_transaction = InvokeTransactionV1 {
            transaction_hash,
            sender_address,
            calldata,
            max_fee: Felt::from(304139049569u64),
            signature: signature_vec,
            nonce,
        };

        let invoke_transaction_v1 = BroadcastedInvokeTransactionV1 {
            sender_address: invoke_transaction.sender_address,
            calldata: invoke_transaction.calldata,
            max_fee: invoke_transaction.max_fee,
            signature: invoke_transaction.signature,
            nonce: invoke_transaction.nonce,
            is_query: false, // Set this to true if it's a query-only transaction
        };
        let broadcasted_transaction = BroadcastedInvokeTransaction::V1(invoke_transaction_v1);

        let response = self
            .client
            .add_invoke_transaction(&broadcasted_transaction)
            .await;
        match response {
            Ok(result) => {
                println!("Transaction successful: {:?}", result);
            }
            Err(err) => {
                eprintln!("Error adding invoke transaction: {:?}", err);
            }
        }
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

    let contract_id = "0x07e2bb02aef8f8cb6851e605d814cf77fe930c812fcc22c851d94ff567341c45";
    let acc = "0x0782897323eb2eeea09bd4c9dd0c6cc559b9452cdddde4dd26b9bbe564411703";

    let method = "name";

    let acc = acc.trim_start_matches("0x");

    let account_bytes = hex::decode(acc).expect("Failed to decode hex string");

    let args: Vec<u8> = account_bytes;

    // match network.query(contract_id, method, args.clone()).await {
    //     Ok(result) => {
    //         println!("{:?}", result);
    //     }
    //     Err(e) => {
    //         println!("Query failed with error: {:?}", e);
    //     }
    // }
    network.mutate(contract_id, method, args).await;

    // match network.mutate(contract_id, method, args).await {
    //     Ok(result) => {
    //         println!("{:?}", result);
    //     }
    //     Err(e) => {
    //         println!("Query failed with error: {:?}", e);
    //     }
    // }
}

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
