use starknet_core::types::{BlockId, BlockTag, Felt, FunctionCall};
use starknet_core::utils::get_selector_from_name;
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

    // async fn mutate(
    //     &self,
    //     contract_id: String,
    //     method: String,
    //     args: Vec<u8>,
    // ) -> Result<Vec<u8>, StarknetError> {
    // }

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
    let rpc_url = Url::parse("https://free-rpc.nethermind.io/mainnet-juno/")
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

    let contract_id = "0x124aeb495b947201f5fac96fd1138e326ad86195b98df6dec9009158a533b49";
    let method = "name";
    let args: Vec<u8> = vec![];

    match network.query(contract_id, method, args).await {
        Ok(result) => {
            println!("Query succeeded with result: {:?}", result);
        }
        Err(e) => {
            println!("Query failed with error: {:?}", e);
        }
    }
    match network.get_nonce(contract_id).await {
        Ok(result) => {
            println!("Query succeeded with result: {:?}", result);
        }
        Err(e) => {
            println!("Query failed with error: {:?}", e);
        }
    }
}

// query, mutate, getnonce

// getNonce
// let result = provider
//     .get_nonce(BlockId::Tag(BlockTag::Latest), felt!("0xCONTRACT_ADDRS"))
//     .await;
//   match result {
//     Ok(nonce) => {
//       println!("{nonce:#?}");
//     }
//     Err(err) => {
//       eprintln!("Error: {err}");
//     }
//   }

// contract_id: AccountId,
// method: String,
// args: Vec<u8>,

// #[derive(Debug, Serialize, Deserialize)]
// #[expect(clippy::exhaustive_enums, reason = "Considered to be exhaustive")]
// pub enum Operation<'a> {
//     Read { method: Cow<'a, str> },
//     Write { method: Cow<'a, str> },
// }

// impl Transport for StarknetTransport<'_> {
//     type Error = StarknetError;

//     async fn send(
//         &self,
//         request: TransportRequest<'_>,
//         payload: Vec<u8>,
//     ) -> Result<Vec<u8>, Self::Error> {
//         let Some(network) = self.networks.get(&request.network_id) else {
//             return Err(StarknetError::UnknownNetwork(request.network_id.into_owned()));
//         };

//         let contract_id = request
//             .contract_id
//             .parse()
//             .map_err(StarknetError::InvalidContractId)?;

//         match request.operation {
//             Operation::Read { method } => {
//                 network
//                     .query(contract_id, method.into_owned(), payload)
//                     .await
//             }
//             Operation::Write { method } => {
//                 network
//                     .mutate(contract_id, method.into_owned(), payload)
//                     .await
//             }
//         }
//     }
// }
