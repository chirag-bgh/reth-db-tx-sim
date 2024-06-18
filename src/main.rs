use reth::api::ConfigureEvm;
use reth::providers::ProviderFactory;
use reth::{
    beacon_consensus::EthBeaconConsensus,
    blockchain_tree::{
        BlockchainTree, BlockchainTreeConfig, ShareableBlockchainTree, TreeExternals,
    },
    primitives::{Address, TransactionSigned},
};
use reth_db::{database::Database, open_db_read_only};
use reth_evm_ethereum::{execute::EthExecutorProvider, EthEvmConfig};
use reth_primitives::{
    revm::env::{fill_block_env, fill_tx_env},
    revm_primitives::EVMError,
    ChainSpec, ChainSpecBuilder, TxHash,
};
use reth_provider::providers::StaticFileProvider;
use reth_provider::{providers::BlockchainProvider, BlockReaderIdExt, StateProviderFactory};
use reth_revm::primitives::InvalidTransaction::InvalidChainId;
use reth_revm::{database::StateProviderDatabase, db::CacheDB, primitives::ResultAndState};
use serde::{Deserialize, Serialize};

use std::path::Path;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse<T> {
    jsonrpc: String,
    result: T,
    id: u32,
}

#[tokio::main]
async fn main() {
    let txs = send_rpc_request()
        .await
        .expect("Failed to send RPC request")
        .result;
    let valid_txs_hash = simulate(txs).expect("Failed to simulate transactions");
    println!("Valid transactions: {:?}", valid_txs_hash);
}

async fn send_rpc_request() -> eyre::Result<RpcResponse<Vec<TransactionSigned>>, reqwest::Error> {
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:8545/")
        .header("Content-Type", "application/json")
        .body(
            r#"{"jsonrpc":"2.0","method":"txpoolExt_getCensoredTransactions","params":[],"id":1}"#,
        )
        .send()
        .await?;
    let rpc_response = res.json::<RpcResponse<Vec<TransactionSigned>>>().await?;

    Ok(rpc_response)
}

pub fn simulate(input: Vec<TransactionSigned>) -> eyre::Result<Vec<TxHash>> {
    let reth_runner = Arc::new(reth_runner_builder()?);
    let mut valid_txs_hash = Vec::<TxHash>::new();

    for tx in input {
        loop {
            let result = reth_runner
                .validate_tx(&tx, tx.recover_signer().expect("could not recover signer"));

            match result {
                Result::Ok(result) => {
                    println!(
                        "Transaction {:?}: used gas {}, success: {}",
                        tx.hash,
                        result.result.gas_used(),
                        result.result.is_success()
                    );
                    println!("Number of state changes: {}", result.state.len());
                    valid_txs_hash.push(tx.clone().hash());
                }
                Result::Err(e) => {
                    println!("Reth simulator error: {:?}", e);
                }
            }
        }
    }

    Ok(valid_txs_hash)
}

pub fn reth_runner_builder() -> eyre::Result<RethRunner<Arc<reth_db::mdbx::DatabaseEnv>>> {
    let path = std::env::var("RETH_DB_PATH")?;
    let db_path = Path::new(&path);
    let db = Arc::new(open_db_read_only(db_path, Default::default())?);

    let chain_spec = Arc::new(ChainSpecBuilder::mainnet().build());
    // let factory =
    //     ProviderFactory::new(db.clone(), chain_spec.clone(), db_path.join("static_files"))?;
    let factory = ProviderFactory::new(
        db.clone(),
        chain_spec.clone(),
        StaticFileProvider::read_only(db_path.join("static_files"))?,
    );

    let provider = Arc::new({
        let consensus = Arc::new(EthBeaconConsensus::new(chain_spec.clone()));
        let executor = EthExecutorProvider::ethereum(chain_spec.clone());

        let tree_externals = TreeExternals::new(factory.clone(), consensus, executor);
        let tree = BlockchainTree::new(tree_externals, BlockchainTreeConfig::default(), None)?;
        let blockchain_tree = Arc::new(ShareableBlockchainTree::new(tree));

        BlockchainProvider::new(factory, blockchain_tree)?
    });

    Ok(RethRunner::new(chain_spec, provider))
}

pub struct RethRunner<DB> {
    pub spec: Arc<ChainSpec>,
    pub provider: Arc<BlockchainProvider<DB>>,
}

impl<DB> RethRunner<DB> {
    pub fn new(spec: Arc<ChainSpec>, provider: Arc<BlockchainProvider<DB>>) -> Self {
        Self { spec, provider }
    }
}

impl<DB> RethRunner<DB>
where
    DB: Database,
{
    fn validate_tx(
        &self,
        tx: &TransactionSigned,
        sender: Address,
    ) -> Result<ResultAndState, EVMError<String>> {
        if tx.chain_id().is_none() || tx.chain_id().unwrap() != self.spec.chain().id() {
            return Err(EVMError::Transaction(InvalidChainId));
        }
        if tx.is_eip1559() || tx.is_eip4844() && tx.max_priority_fee_per_gas().unwrap() == 0 {
            return Err(EVMError::Custom("Priority fee is 0".to_string()));
        }

        let latest_block_header = self
            .provider
            .latest_header()
            .map_err(|_e| EVMError::Database(String::from("Error fetching latest sealed header")))?
            .unwrap();

        let latest_state = self
            .provider
            .state_by_block_hash(latest_block_header.hash())
            .map_err(|_| EVMError::Database(String::from("Error fetching latest state")))?;

        let state = Arc::new(StateProviderDatabase::new(latest_state));
        let db = CacheDB::new(Arc::clone(&state));
        let evm_config = EthEvmConfig::default();
        let mut evm = evm_config.evm(db);
        fill_block_env(evm.block_mut(), &self.spec, &latest_block_header, true);
        fill_tx_env(evm.tx_mut(), tx, sender);

        evm.transact()
            .map_err(|_| EVMError::Database(String::from("Error executing transaction")))
    }
}
