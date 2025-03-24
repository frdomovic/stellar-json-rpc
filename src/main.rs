use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;
use std::time::Instant;

use stellar_baselib::xdr::{self, ReadXdr};

use soroban_client::contract::{ContractBehavior, Contracts};

use soroban_client::error::Error;
use soroban_client::keypair::{Keypair, KeypairBehavior};

use soroban_client::network::{NetworkPassphrase, Networks};
use soroban_client::server::{Options, Server};

use soroban_client::soroban_rpc::{
    GetTransactionResponse, RawSimulateHostFunctionResult, RawSimulateTransactionResponse, SendTransactionStatus
};
use soroban_client::transaction::{TransactionBehavior, TransactionBuilder};
use soroban_client::transaction_builder::TransactionBuilderBehavior;
use soroban_client::xdr::{ScBytes, ScVal};

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
struct ContextData {
    contract_id: String,
    application_id: String,
    members: Vec<u8>,
}

async fn query(
    server: &Server,
    keypair: &Keypair,
    contract_id: &str,
    method: &str,
    params: Vec<u8>,
) -> Option<Vec<u8>> {
    let contract: Contracts = Contracts::new(contract_id).unwrap();
    let network = Networks::testnet();
    let account = server
        .get_account(keypair.public_key().as_str())
        .await
        .unwrap();

    let source_account = Rc::new(RefCell::new(account));

    let params = if params.is_empty() {
        None
    } else {
        let sc_bytes = ScBytes::try_from(params).unwrap();
        let scval_bytes = ScVal::Bytes(sc_bytes);
        Some(vec![scval_bytes])
    };

    let transaction = TransactionBuilder::new(source_account, network, None)
        .fee(10000u32)
        .add_operation(contract.call(method, params))
        .set_timeout(15)
        .expect("Transaction timeout")
        .build();

    let result: Result<RawSimulateTransactionResponse, Error> = server.simulate_transaction(transaction.clone(), None).await;
    let xdr_results: Vec<RawSimulateHostFunctionResult> = result.unwrap().results.unwrap();
    
    if let Some(xdr) = xdr_results.first() {
        if let Some(xdr_bytes) = &xdr.xdr {
            let xdr_bytes = base64::decode(xdr_bytes).expect("Failed to decode base64 XDR");
            let cursor = Cursor::new(xdr_bytes);
            let mut limited = xdr::Limited::new(cursor, xdr::Limits::none());
            if let Ok(ScVal::Bytes(bytes)) = ScVal::read_xdr(&mut limited) {
                Some(bytes.into())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

async fn mutate(
    server: &Server,
    keypair: &Keypair,
    contract_id: &str,
    method: &str,
    params: Vec<u8>,
) -> Option<Vec<u8>> {
    let contract: Contracts = Contracts::new(contract_id).unwrap();
    let network = Networks::testnet();
    let account = server
        .get_account(keypair.public_key().as_str())
        .await
        .unwrap();

    let source_account = Rc::new(RefCell::new(account));

    let params = if params.is_empty() {
        None
    } else {
        let sc_bytes = ScBytes::try_from(params).unwrap();
        let scval_bytes = ScVal::Bytes(sc_bytes);
        Some(vec![scval_bytes])
    };

    let transaction = TransactionBuilder::new(source_account, network, None)
        .fee(10000u32)
        .add_operation(contract.call(method, params))
        .set_timeout(15)
        .expect("Transaction timeout")
        .build();

    let signed_tx = {
        let prepared_tx = server.prepare_transaction(transaction, network).await;
        if let Ok(mut tx) = prepared_tx {
            tx.sign(&[keypair.clone()]);
            Some(tx.clone())
        } else {
            println!("Failed to create tx: {:?}", prepared_tx);
            None
        }
    };

    let result = if let Some(tx) = signed_tx {
        match server.send_transaction(tx).await {
            Ok(response) => {
                let hash = response.base.hash;
                let status = response.base.status;
                let start = Instant::now();

                match status {
                    SendTransactionStatus::Pending | SendTransactionStatus::Success => loop {
                        let r = server
                            .get_transaction(hash.as_str())
                            .await
                            .map_err(|err| {
                                println!("Error: {:?}", err);
                                None::<GetTransactionResponse>
                            })
                            .unwrap();
                        if let GetTransactionResponse::Successful(info) = r {
                            break Some(info.returnValue);
                        } else if Instant::now().duration_since(start).as_secs() > 35 {
                            break None;
                        } else if let GetTransactionResponse::Failed(f) = r {
                            println!("Failed: {:?}", f);
                            break None;
                        } else {
                            continue;
                        }
                    },
                    _ => Some(None),
                }
            }
            Err(err) => {
                println!("Error: {}", err);
                Some(None)
            }
        }
    } else {
        println!("Error: {:?}", signed_tx);
        Some(None)
    };

    if let Some(Some(val)) = result {
        match val {
            ScVal::Bytes(bytes) => {
                let raw_bytes: Vec<u8> = bytes.into();
                Some(raw_bytes)
            }
            ScVal::Void => None,
            other => {
                println!("Unexpected value format: {:?}", other);
                None
            }
        }
    } else {
        None
    }
}

fn get_server() -> Server {
    const RPC_URL: &str = "https://soroban-testnet.stellar.org";
    const OPTIONS: Options = Options {
        allow_http: None,
        timeout: Some(1000),
        headers: None,
    };
    Server::new(RPC_URL, OPTIONS).unwrap()
}

#[tokio::main]
async fn main() {
    let server = get_server();
    let contract_id = "CDOQVQE4UARLUXZHOT5YVKTE4UV4CT5PK6UXYOHILWQNSSO4POGJF6PS";
    let keypair =
        Keypair::from_secret("SDF7RFYEIFGPUKL2EWJCVRR3XENJEMBAR26COHD4VTRUYG3WD57EHSJM").unwrap();
    let contract_data: ContextData = ContextData {
        contract_id: contract_id.to_string(),
        application_id: "134".to_string(),
        members: vec![1, 1, 1, 1, 1],
    };
    let params = bincode::serialize(&contract_data).unwrap();
    
    let response = mutate(&server, &keypair, contract_id, "save_data", params.clone()).await;

    println!("Mutate Response: {:?}", response);

    let response = query(&server, &keypair, contract_id, "get_data", vec![]).await;
    println!("Set Data: {:?}", params);
    println!("Query set data Response: {:?}", response.unwrap());
}
