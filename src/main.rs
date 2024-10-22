use bs58;
use hex;
use starknet_core::types::{
    BlockId, BlockTag, BroadcastedInvokeTransaction, BroadcastedInvokeTransactionV1, ContractClass,
    Felt, FunctionCall, InvokeTransactionV1,
};
use starknet_core::utils::get_selector_from_name;
use starknet_crypto::{poseidon_hash_many, Signature};
use starknet_providers::jsonrpc::HttpTransport;
use starknet_providers::{JsonRpcClient, Provider, Url};
use std::collections::BTreeMap;
use std::{borrow::Cow, str::FromStr};
use thiserror::Error;
use types::{Application, ContextId, ContextIdentity};

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

fn application_to_felt_vec(application: &Application) -> Vec<Felt> {
    let mut felt_vec = Vec::new();
    
    // Add single fields
    felt_vec.push(application.id);
    felt_vec.push(application.blob);
    felt_vec.push(application.size);
    
    // Add collection fields (source and metadata)
    felt_vec.extend(application.source.iter().cloned());
    felt_vec.extend(application.metadata.iter().cloned());
    
    felt_vec
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

        let application = Application {
            id: Felt::from_raw(6382179),
            blob: 7092165981550440290i64.into(),
            size: 0.into(),
            source: [7161124082558530159i64.into()].to_vec(),
            metadata: [1835365473.into()].to_vec(),
        };

        let calldata = application_to_felt_vec(&application);

        let invoke_transaction_v1 = BroadcastedInvokeTransactionV1 {
            sender_address,
            calldata,

            max_fee: Felt::from(304139049569u64),
            signature: signature_vec,
            nonce,
            is_query: false,
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
    let application = Application {
        id: 6382179.into(),
        blob: 7092165981550440290i64.into(),
        size: 0.into(),
        source: [7161124082558530159i64.into()].to_vec(),
        metadata: [1835365473.into()].to_vec(),
    };

    println!("Application: {:?}", application);


    network.mutate(contract_id, method, args).await;
}

pub struct SignedReq {
    payload: Vec<Felt>,
    signature: (Felt, Felt),
    public_key: Felt,
}

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
