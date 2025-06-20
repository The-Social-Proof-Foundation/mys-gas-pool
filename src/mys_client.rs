// Copyright (c) Mysten Labs, Inc.
// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use crate::object_locks::MultiGetObjectOwners;
use crate::types::GasCoin;
use crate::{retry_forever, retry_with_max_attempts};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use itertools::Itertools;
use std::collections::HashMap;
use std::time::Duration;
use mys_json_rpc_types::MysTransactionBlockEffectsAPI;
use mys_json_rpc_types::{
    MysData, MysObjectDataOptions, MysObjectResponse, MysTransactionBlockEffects,
    MysTransactionBlockResponseOptions,
};
use mys_sdk::MysClientBuilder;
use mys_types::base_types::{ObjectID, ObjectRef, MysAddress};
use mys_types::coin::{PAY_MODULE_NAME, PAY_SPLIT_N_FUNC_NAME};
use mys_types::gas_coin::GAS;
use mys_types::object::Owner;
use mys_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use mys_types::quorum_driver_types::ExecuteTransactionRequestType;
use mys_types::transaction::{
    Argument, ObjectArg, ProgrammableTransaction, Transaction, TransactionKind,
};
use mys_types::MYS_FRAMEWORK_PACKAGE_ID;
use tap::TapFallible;
use tracing::{debug, info};

#[derive(Clone)]
pub struct MysClient {
    mys_client: mys_sdk::MysClient,
}

impl MysClient {
    pub async fn new(fullnode_url: &str, basic_auth: Option<(String, String)>) -> Self {
        let mut mys_client_builder = MysClientBuilder::default().max_concurrent_requests(100000);
        if let Some((username, password)) = basic_auth {
            mys_client_builder = mys_client_builder.basic_auth(username, password);
        }
        let mys_client = mys_client_builder.build(fullnode_url).await
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to connect to MySocial fullnode at '{}'. \
                    Please check that the FULLNODE_URL environment variable is set to a valid MySocial RPC endpoint. \
                    Error: {:?}",
                    fullnode_url, err
                );
            });
        Self { mys_client }
    }

    pub async fn get_all_owned_mys_coins_above_balance_threshold(
        &self,
        address: MysAddress,
        balance_threshold: u64,
    ) -> Vec<GasCoin> {
        info!(
            "Querying all gas coins owned by sponsor address {} that has at least {} balance",
            address, balance_threshold
        );
        let mut cursor = None;
        let mut coins = Vec::new();
        loop {
            let page = retry_forever!(async {
                self.mys_client
                    .coin_read_api()
                    .get_coins(address, None, cursor.clone(), None)
                    .await
                    .tap_err(|err| debug!("Failed to get owned gas coins: {:?}", err))
            })
            .unwrap();
            for coin in page.data {
                if coin.balance >= balance_threshold {
                    coins.push(GasCoin {
                        object_ref: coin.object_ref(),
                        balance: coin.balance,
                    });
                }
            }
            if page.has_next_page {
                cursor = page.next_cursor;
            } else {
                break;
            }
        }
        coins
    }

    pub async fn get_reference_gas_price(&self) -> u64 {
        retry_forever!(async {
            self.mys_client
                .governance_api()
                .get_reference_gas_price()
                .await
                .tap_err(|err| debug!("Failed to get reference gas price: {:?}", err))
        })
        .unwrap()
    }

    pub async fn get_latest_gas_objects(
        &self,
        object_ids: impl IntoIterator<Item = ObjectID>,
    ) -> HashMap<ObjectID, Option<GasCoin>> {
        let tasks: FuturesUnordered<_> = object_ids
            .into_iter()
            .chunks(50)
            .into_iter()
            .map(|chunk| {
                let chunk: Vec<_> = chunk.collect();
                let mys_client = self.mys_client.clone();
                tokio::spawn(async move {
                    retry_forever!(async {
                        let chunk = chunk.clone();
                        let result = mys_client
                            .clone()
                            .read_api()
                            .multi_get_object_with_options(
                                chunk.clone(),
                                MysObjectDataOptions::default().with_bcs(),
                            )
                            .await
                            .map_err(anyhow::Error::from)?;
                        if result.len() != chunk.len() {
                            anyhow::bail!(
                                "Unable to get all gas coins, got {} out of {}",
                                result.len(),
                                chunk.len()
                            );
                        }
                        Ok(chunk.into_iter().zip(result).collect::<Vec<_>>())
                    })
                    .unwrap()
                })
            })
            .collect();
        let objects: Vec<_> = tasks.collect().await;
        let objects: Vec<_> = objects.into_iter().flat_map(|r| r.unwrap()).collect();
        objects
            .into_iter()
            .map(|(id, response)| {
                let object = match Self::try_get_mys_coin_balance(&response) {
                    Some(coin) => {
                        debug!("Got updated gas coin info: {:?}", coin);
                        Some(coin)
                    }
                    None => {
                        debug!("Object no longer exists: {:?}", id);
                        None
                    }
                };
                (id, object)
            })
            .collect()
    }

    pub fn construct_coin_split_pt(
        gas_coin: Argument,
        split_count: u64,
    ) -> ProgrammableTransaction {
        let mut pt_builder = ProgrammableTransactionBuilder::new();
        let pure_arg = pt_builder.pure(split_count).unwrap();
        pt_builder.programmable_move_call(
            MYS_FRAMEWORK_PACKAGE_ID,
            PAY_MODULE_NAME.into(),
            PAY_SPLIT_N_FUNC_NAME.into(),
            vec![GAS::type_tag()],
            vec![gas_coin, pure_arg],
        );
        pt_builder.finish()
    }

    pub async fn calibrate_gas_cost_per_object(
        &self,
        sponsor_address: MysAddress,
        gas_coin: &GasCoin,
    ) -> u64 {
        const SPLIT_COUNT: u64 = 500;
        let mut pt_builder = ProgrammableTransactionBuilder::new();
        let object_arg = pt_builder
            .obj(ObjectArg::ImmOrOwnedObject(gas_coin.object_ref))
            .unwrap();
        let pure_arg = pt_builder.pure(SPLIT_COUNT).unwrap();
        pt_builder.programmable_move_call(
            MYS_FRAMEWORK_PACKAGE_ID,
            PAY_MODULE_NAME.into(),
            PAY_SPLIT_N_FUNC_NAME.into(),
            vec![GAS::type_tag()],
            vec![object_arg, pure_arg],
        );
        let pt = pt_builder.finish();
        let response = retry_forever!(async {
            self.mys_client
                .read_api()
                .dev_inspect_transaction_block(
                    sponsor_address,
                    TransactionKind::ProgrammableTransaction(pt.clone()),
                    None,
                    None,
                    None,
                )
                .await
        })
        .unwrap();
        let gas_used = response.effects.gas_cost_summary().gas_used();
        // Multiply by 2 to be conservative and resilient to precision loss.
        gas_used / SPLIT_COUNT * 2
    }

    pub async fn execute_transaction(
        &self,
        tx: Transaction,
        max_attempts: usize,
    ) -> anyhow::Result<MysTransactionBlockEffects> {
        let digest = *tx.digest();
        debug!(?digest, "Executing transaction: {:?}", tx);
        let response = retry_with_max_attempts!(
            async {
                self.mys_client
                    .quorum_driver_api()
                    .execute_transaction_block(
                        tx.clone(),
                        MysTransactionBlockResponseOptions::new().with_effects(),
                        Some(ExecuteTransactionRequestType::WaitForEffectsCert),
                    )
                    .await
                    .tap_err(|err| debug!(?digest, "execute_transaction error: {:?}", err))
                    .map_err(anyhow::Error::from)
                    .and_then(|r| r.effects.ok_or_else(|| anyhow::anyhow!("No effects")))
            },
            max_attempts
        );
        debug!(?digest, "Transaction execution response: {:?}", response);
        response
    }

    /// Wait for a known valid object version to be available on the fullnode.
    pub async fn wait_for_object(&self, obj_ref: ObjectRef) {
        loop {
            let response = self
                .mys_client
                .read_api()
                .get_object_with_options(obj_ref.0, MysObjectDataOptions::default())
                .await;
            if let Ok(MysObjectResponse {
                data: Some(data), ..
            }) = response
            {
                if data.version == obj_ref.1 {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn try_get_mys_coin_balance(object: &MysObjectResponse) -> Option<GasCoin> {
        let data = object.data.as_ref()?;
        let object_ref = data.object_ref();
        let move_obj = data.bcs.as_ref()?.try_as_move()?;
        if move_obj.type_ != mys_types::gas_coin::GasCoin::type_() {
            return None;
        }
        let gas_coin: mys_types::gas_coin::GasCoin = bcs::from_bytes(&move_obj.bcs_bytes).ok()?;
        Some(GasCoin {
            object_ref,
            balance: gas_coin.value(),
        })
    }
}

#[async_trait::async_trait]
impl MultiGetObjectOwners for MysClient {
    async fn multi_get_object_owners(
        &self,
        object_ids: Vec<ObjectID>,
    ) -> anyhow::Result<HashMap<ObjectID, (Owner, u64)>> {
        retry_with_max_attempts!(
            async {
                let results = self
                    .mys_client
                    .read_api()
                    .multi_get_object_with_options(
                        object_ids.clone(),
                        MysObjectDataOptions::default().with_owner(),
                    )
                    .await
                    .tap_err(|err| debug!("Failed to get object owners: {:?}", err))?;
                let mut owner_map = HashMap::new();
                for r in results {
                    let Some(data) = &r.data else {
                        anyhow::bail!("Failed to get object owner: {:?}", r);
                    };
                    let Some(owner) = &data.owner else {
                        anyhow::bail!("Failed to get object owner: {:?}", r);
                    };
                    let version = data.version.value();
                    owner_map.insert(data.object_id, (owner.clone(), version));
                }
                Ok(owner_map)
            },
            3
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mys_types::crypto::get_account_key_pair;
    use mys_types::object::Object;
    use test_cluster::{TestCluster, TestClusterBuilder};

    async fn create_test_cluster(objects: Vec<Object>) -> TestCluster {
        TestClusterBuilder::new()
            .with_objects(objects)
            .build()
            .await
    }

    #[tokio::test]
    async fn test_multi_get_object_owners() {
        // Create multiple key pairs to represent different owners
        let (owner1, _) = get_account_key_pair();
        let (owner2, _) = get_account_key_pair();

        // Create test objects with different owners
        let mut objects = vec![];

        // Create object owned by owner1
        let obj1 = Object::with_owner_for_testing(owner1);
        objects.push(obj1.clone());

        // Create object owned by owner2
        let obj2 = Object::with_owner_for_testing(owner2);
        objects.push(obj2.clone());

        // Create immutable object
        let obj3 = Object::immutable_for_testing();
        objects.push(obj3.clone());

        // Create shared object
        let obj4 = Object::shared_for_testing();
        objects.push(obj4.clone());

        // Create test cluster with our objects
        let test_cluster = create_test_cluster(objects).await;
        let mys_client = MysClient::new(&test_cluster.rpc_url(), None).await;

        // Get object IDs to query
        let object_ids = vec![obj1.id(), obj2.id(), obj3.id(), obj4.id()];

        // Query owners
        let owner_map = mys_client
            .multi_get_object_owners(object_ids.clone())
            .await
            .unwrap();

        // Verify results
        assert_eq!(
            owner_map.get(&obj1.id()),
            Some(&(Owner::AddressOwner(owner1), obj1.version().value()))
        );
        assert_eq!(
            owner_map.get(&obj2.id()),
            Some(&(Owner::AddressOwner(owner2), obj2.version().value()))
        );
        assert_eq!(
            owner_map.get(&obj3.id()),
            Some(&(Owner::Immutable, obj3.version().value()))
        );
        assert_eq!(
            owner_map.get(&obj4.id()),
            Some(&(
                Owner::Shared {
                    initial_shared_version: obj4.version(),
                },
                obj4.version().value()
            ))
        );

        // Verify we got all objects
        assert_eq!(owner_map.len(), object_ids.len());
    }
}
