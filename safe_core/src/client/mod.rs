// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// User Account information.
pub mod account;
/// Core client used for testing purposes.
#[cfg(any(test, feature = "testing"))]
pub mod core_client;
/// `MDataInfo` utilities.
pub mod mdata_info;
/// Various APIs wrapped to provide resiliance for common network operations.
pub mod recoverable_apis;

mod id;
#[cfg(feature = "mock-network")]
mod mock;

pub use self::account::ClientKeys;
pub use self::id::SafeKey;
pub use self::mdata_info::MDataInfo;
#[cfg(feature = "mock-network")]
pub use self::mock::vault::mock_vault_path;
#[cfg(feature = "mock-network")]
pub use self::mock::ConnectionManager as MockConnectionManager;

#[cfg(feature = "mock-network")]
use self::mock::ConnectionManager;
use crate::config_handler::Config;
#[cfg(not(feature = "mock-network"))]
use crate::connection_manager::ConnectionManager;
use crate::crypto::{shared_box, shared_secretbox};
use crate::errors::CoreError;
use crate::event_loop::{CoreFuture, CoreMsgTx};
use crate::ipc::BootstrapConfig;
use crate::network_event::{NetworkEvent, NetworkTx};
use crate::utils::FutureExt;
use futures::{future, sync::mpsc, Future};
use lazy_static::lazy_static;
use log::trace;
use lru_cache::LruCache;
use safe_nd::{
    AccessList, Address, AppPermissions, AppendOperation, ClientFullId, Coins, ExpectedVersions,
    IData, IDataAddress, LoginPacket, MData, MDataAddress, MDataEntries, MDataEntryActions,
    MDataPermissionSet, MDataSeqEntries, MDataSeqEntryActions, MDataSeqValue,
    MDataUnseqEntryActions, MDataValue, MDataValues, Message, MessageId, Owner, PrivateAccessList,
    PrivateUserAccess, PublicAccessList, PublicId, PublicKey, PublicUserAccess, Request,
    RequestType, Response, SeqMutableData, Sequence, SequenceEntry, Transaction, UnseqMutableData,
    User, Value, Values, Version, XorName,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;
use threshold_crypto;
use tokio::runtime::current_thread::{block_on_all, Handle};
use unwrap::unwrap;

/// Capacity of the immutable data cache.
pub const IMMUT_DATA_CACHE_SIZE: usize = 300;

// FIXME: move to conn manager
// const CONNECTION_TIMEOUT_SECS: u64 = 40;

lazy_static! {
    /// Expected cost of mutation operations.
    pub static ref COST_OF_PUT: Coins = unwrap!(Coins::from_nano(1));
}

/// Return the `crust::Config` associated with the `crust::Service` (if any).
pub fn bootstrap_config() -> Result<BootstrapConfig, CoreError> {
    Ok(Config::new().quic_p2p.hard_coded_contacts)
}

fn send(client: &impl Client, request: Request) -> Box<CoreFuture<Response>> {
    // `sign` should be false for GETs on published data, true otherwise.
    let sign = request.get_type() != RequestType::PublicGet;
    let request = client.compose_message(request, sign);
    let inner = client.inner();
    let cm = &mut inner.borrow_mut().connection_manager;
    cm.send(&client.public_id(), &request)
}

// Sends a mutation request to a new routing.
fn send_mutation(client: &impl Client, req: Request) -> Box<CoreFuture<()>> {
    Box::new(send(client, req).and_then(move |result| {
        trace!("mutation result: {:?}", result);
        match result {
            Response::Mutation(result) => result.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        }
    }))
}

// Sends a request either using a default user's identity, or reconnects to another group
// to use another identity.
macro_rules! send_as {
    ($client:expr, $request:expr, $response:path, $secret_key:expr) => {
        send_as_helper($client, $request, $secret_key)
            .and_then(|res| match res {
                $response(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    };
}

fn send_as_helper(
    client: &impl Client,
    request: Request,
    client_id: Option<&ClientFullId>,
) -> Box<CoreFuture<Response>> {
    let (message, identity) = match client_id {
        Some(id) => (sign_request(request, id), SafeKey::client(id.clone())),
        None => (client.compose_message(request, true), client.full_id()),
    };

    let pub_id = identity.public_id();

    let inner = client.inner();

    let cm = &mut inner.borrow_mut().connection_manager;
    let mut cm2 = cm.clone();

    Box::new(
        cm.bootstrap(identity)
            .and_then(move |_| cm2.send(&pub_id, &message)),
    )
}

/// Trait providing an interface for self-authentication client implementations, so they can
/// interface all requests from high-level APIs to the actual routing layer and manage all
/// interactions with it. Clients are non-blocking, with an asynchronous API using the futures
/// abstraction from the futures-rs crate.
pub trait Client: Clone + 'static {
    /// Associated message type.
    type Context;

    /// Return the client's ID.
    fn full_id(&self) -> SafeKey;

    /// Return the client's public ID.
    fn public_id(&self) -> PublicId {
        self.full_id().public_id()
    }

    /// Returns the client's public key.
    fn public_key(&self) -> PublicKey {
        self.full_id().public_key()
    }

    /// Returns the client's owner key.
    fn owner_key(&self) -> PublicKey;

    /// Return a `crust::Config` if the `Client` was initialized with one.
    fn config(&self) -> Option<BootstrapConfig>;

    /// Return an associated `ClientInner` type which is expected to contain fields associated with
    /// the implementing type.
    fn inner(&self) -> Rc<RefCell<Inner<Self, Self::Context>>>;

    /// Return the public encryption key.
    fn public_encryption_key(&self) -> threshold_crypto::PublicKey;

    /// Return the secret encryption key.
    fn secret_encryption_key(&self) -> shared_box::SecretKey;

    /// Return the public and secret encryption keys.
    fn encryption_keypair(&self) -> (threshold_crypto::PublicKey, shared_box::SecretKey) {
        (self.public_encryption_key(), self.secret_encryption_key())
    }

    /// Return the symmetric encryption key.
    fn secret_symmetric_key(&self) -> shared_secretbox::Key;

    /// Create a `Message` from the given request.
    /// This function adds the requester signature and message ID.
    fn compose_message(&self, request: Request, sign: bool) -> Message {
        let message_id = MessageId::new();

        let signature = if sign {
            Some(
                self.full_id()
                    .sign(&unwrap!(bincode::serialize(&(&request, message_id)))),
            )
        } else {
            None
        };

        Message::Request {
            request,
            message_id,
            signature,
        }
    }

    /// Set request timeout.
    fn set_timeout(&self, duration: Duration) {
        let inner = self.inner();
        inner.borrow_mut().timeout = duration;
    }

    /// Restart the client and reconnect to the network.
    fn restart_network(&self) -> Result<(), CoreError> {
        trace!("Restarting the network connection");

        let inner = self.inner();
        let mut inner = inner.borrow_mut();

        inner.connection_manager.restart_network();

        inner.net_tx.unbounded_send(NetworkEvent::Connected)?;

        Ok(())
    }

    /// Put unsequenced mutable data to the network
    fn put_unseq_mutable_data(&self, data: UnseqMutableData) -> Box<CoreFuture<()>> {
        trace!("Put Unsequenced MData at {:?}", data.name());
        send_mutation(self, Request::PutMData(MData::Unseq(data)))
    }

    /// Transfer coin balance
    fn transfer_coins(
        &self,
        client_id: Option<&ClientFullId>,
        destination: XorName,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> Box<CoreFuture<Transaction>> {
        trace!("Transfer {} coins to {:?}", amount, destination);
        send_as!(
            self,
            Request::TransferCoins {
                destination,
                amount,
                transaction_id: transaction_id.unwrap_or_else(rand::random),
            },
            Response::Transaction,
            client_id
        )
    }

    /// Creates a new balance on the network.
    fn create_balance(
        &self,
        client_id: Option<&ClientFullId>,
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
    ) -> Box<CoreFuture<Transaction>> {
        trace!(
            "Create a new balance for {:?} with {} coins.",
            new_balance_owner,
            amount
        );

        send_as!(
            self,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: transaction_id.unwrap_or_else(rand::random),
            },
            Response::Transaction,
            client_id
        )
    }

    /// Insert a given login packet at the specified destination
    fn insert_login_packet_for(
        &self,
        client_id: Option<&ClientFullId>,
        new_owner: PublicKey,
        amount: Coins,
        transaction_id: Option<u64>,
        new_login_packet: LoginPacket,
    ) -> Box<CoreFuture<Transaction>> {
        trace!(
            "Insert a login packet for {:?} preloading the wallet with {} coins.",
            new_owner,
            amount
        );

        let transaction_id = transaction_id.unwrap_or_else(rand::random);
        send_as!(
            self,
            Request::CreateLoginPacketFor {
                new_owner,
                amount,
                transaction_id,
                new_login_packet,
            },
            Response::Transaction,
            client_id
        )
    }

    /// Get the current coin balance.
    fn get_balance(&self, client_id: Option<&ClientFullId>) -> Box<CoreFuture<Coins>> {
        trace!("Get balance for {:?}", client_id);

        send_as!(self, Request::GetBalance, Response::GetBalance, client_id)
    }

    /// Put immutable data to the network.
    fn put_idata(&self, data: impl Into<IData>) -> Box<CoreFuture<()>> {
        let idata: IData = data.into();
        trace!("Put IData at {:?}", idata.name());
        send_mutation(self, Request::PutIData(idata))
    }

    /// Get immutable data from the network. If the data exists locally in the cache then it will be
    /// immediately returned without making an actual network request.
    fn get_idata(&self, address: IDataAddress) -> Box<CoreFuture<IData>> {
        trace!("Fetch Immutable Data");

        let inner = self.inner();
        if let Some(data) = inner.borrow_mut().cache.get_mut(&address) {
            trace!("ImmutableData found in cache.");
            return future::ok(data.clone()).into_box();
        }

        let inner = Rc::downgrade(&self.inner());
        send(self, Request::GetIData(address))
            .and_then(|res| match res {
                Response::GetIData(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .map(move |data| {
                if let Some(inner) = inner.upgrade() {
                    // Put to cache
                    let _ = inner
                        .borrow_mut()
                        .cache
                        .insert(*data.address(), data.clone());
                }
                data
            })
            .into_box()
    }

    /// Delete unpublished immutable data from the network.
    fn del_unpub_idata(&self, name: XorName) -> Box<CoreFuture<()>> {
        let inner = self.inner();
        if inner
            .borrow_mut()
            .cache
            .remove(&IDataAddress::Unpub(name))
            .is_some()
        {
            trace!("Deleted UnpubImmutableData from cache.");
        }

        let _ = Rc::downgrade(&self.inner());
        trace!("Delete Unpublished IData at {:?}", name);
        send_mutation(self, Request::DeleteUnpubIData(IDataAddress::Unpub(name)))
    }

    /// Put sequenced mutable data to the network
    fn put_seq_mutable_data(&self, data: SeqMutableData) -> Box<CoreFuture<()>> {
        trace!("Put Sequenced MData at {:?}", data.name());
        send_mutation(self, Request::PutMData(MData::Seq(data)))
    }

    /// Fetch unpublished mutable data from the network
    fn get_unseq_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<UnseqMutableData>> {
        trace!("Fetch Unsequenced Mutable Data");

        send(self, Request::GetMData(MDataAddress::Unseq { name, tag }))
            .and_then(|res| match res {
                Response::GetMData(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Unseq(data) => Ok(data),
                        MData::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Fetch the value for a given key in a sequenced mutable data
    fn get_seq_mdata_value(
        &self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Box<CoreFuture<MDataSeqValue>> {
        trace!("Fetch MDataValue for {:?}", name);

        send(
            self,
            Request::GetMDataValue {
                address: MDataAddress::Seq { name, tag },
                key,
            },
        )
        .and_then(|res| match res {
            Response::GetMDataValue(res) => {
                res.map_err(CoreError::from).and_then(|value| match value {
                    MDataValue::Seq(val) => Ok(val),
                    MDataValue::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Fetch the value for a given key in a sequenced mutable data
    fn get_unseq_mdata_value(
        &self,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
    ) -> Box<CoreFuture<Vec<u8>>> {
        trace!("Fetch MDataValue for {:?}", name);

        send(
            self,
            Request::GetMDataValue {
                address: MDataAddress::Unseq { name, tag },
                key,
            },
        )
        .and_then(|res| match res {
            Response::GetMDataValue(res) => {
                res.map_err(CoreError::from).and_then(|value| match value {
                    MDataValue::Unseq(val) => Ok(val),
                    MDataValue::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Fetch sequenced mutable data from the network
    fn get_seq_mdata(&self, name: XorName, tag: u64) -> Box<CoreFuture<SeqMutableData>> {
        trace!("Fetch Sequenced Mutable Data");

        send(self, Request::GetMData(MDataAddress::Seq { name, tag }))
            .and_then(|res| match res {
                Response::GetMData(res) => {
                    res.map_err(CoreError::from).and_then(|mdata| match mdata {
                        MData::Seq(data) => Ok(data),
                        MData::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Mutates sequenced `MutableData` entries in bulk
    fn mutate_seq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MDataSeqEntryActions,
    ) -> Box<CoreFuture<()>> {
        trace!("Mutate MData for {:?}", name);

        send_mutation(
            self,
            Request::MutateMDataEntries {
                address: MDataAddress::Seq { name, tag },
                actions: MDataEntryActions::Seq(actions),
            },
        )
    }

    /// Mutates unsequenced `MutableData` entries in bulk
    fn mutate_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
        actions: MDataUnseqEntryActions,
    ) -> Box<CoreFuture<()>> {
        trace!("Mutate MData for {:?}", name);

        send_mutation(
            self,
            Request::MutateMDataEntries {
                address: MDataAddress::Unseq { name, tag },
                actions: MDataEntryActions::Unseq(actions),
            },
        )
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_seq_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<SeqMutableData>> {
        trace!("GetMDataShell for {:?}", name);

        send(
            self,
            Request::GetMDataShell(MDataAddress::Seq { name, tag }),
        )
        .and_then(|res| match res {
            Response::GetMDataShell(res) => {
                res.map_err(CoreError::from).and_then(|mdata| match mdata {
                    MData::Seq(data) => Ok(data),
                    _ => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Get a shell (bare bones) version of `MutableData` from the network.
    fn get_unseq_mdata_shell(&self, name: XorName, tag: u64) -> Box<CoreFuture<UnseqMutableData>> {
        trace!("GetMDataShell for {:?}", name);

        send(
            self,
            Request::GetMDataShell(MDataAddress::Unseq { name, tag }),
        )
        .and_then(|res| match res {
            Response::GetMDataShell(res) => {
                res.map_err(CoreError::from).and_then(|mdata| match mdata {
                    MData::Unseq(data) => Ok(data),
                    _ => Err(CoreError::ReceivedUnexpectedData),
                })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Get a current version of `MutableData` from the network.
    fn get_mdata_version(&self, address: MDataAddress) -> Box<CoreFuture<u64>> {
        trace!("GetMDataVersion for {:?}", address);

        send(self, Request::GetMDataVersion(address))
            .and_then(|res| match res {
                Response::GetMDataVersion(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Return a complete list of entries in `MutableData`.
    fn list_unseq_mdata_entries(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<BTreeMap<Vec<u8>, Vec<u8>>>> {
        trace!("ListMDataEntries for {:?}", name);

        send(
            self,
            Request::ListMDataEntries(MDataAddress::Unseq { name, tag }),
        )
        .and_then(|res| match res {
            Response::ListMDataEntries(res) => {
                res.map_err(CoreError::from)
                    .and_then(|entries| match entries {
                        MDataEntries::Unseq(data) => Ok(data),
                        MDataEntries::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Return a complete list of entries in `MutableData`.
    fn list_seq_mdata_entries(&self, name: XorName, tag: u64) -> Box<CoreFuture<MDataSeqEntries>> {
        trace!("ListSeqMDataEntries for {:?}", name);

        send(
            self,
            Request::ListMDataEntries(MDataAddress::Seq { name, tag }),
        )
        .and_then(|res| match res {
            Response::ListMDataEntries(res) => {
                res.map_err(CoreError::from)
                    .and_then(|entries| match entries {
                        MDataEntries::Seq(data) => Ok(data),
                        MDataEntries::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Return a list of keys in `MutableData` stored on the network.
    fn list_mdata_keys(&self, address: MDataAddress) -> Box<CoreFuture<BTreeSet<Vec<u8>>>> {
        trace!("ListMDataKeys for {:?}", address);

        send(self, Request::ListMDataKeys(address))
            .and_then(|res| match res {
                Response::ListMDataKeys(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Return a list of values in a Sequenced Mutable Data
    fn list_seq_mdata_values(
        &self,
        name: XorName,
        tag: u64,
    ) -> Box<CoreFuture<Vec<MDataSeqValue>>> {
        trace!("List MDataValues for {:?}", name);

        send(
            self,
            Request::ListMDataValues(MDataAddress::Seq { name, tag }),
        )
        .and_then(|res| match res {
            Response::ListMDataValues(res) => {
                res.map_err(CoreError::from)
                    .and_then(|values| match values {
                        MDataValues::Seq(data) => Ok(data),
                        MDataValues::Unseq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Return the permissions set for a particular user
    fn list_mdata_user_permissions(
        &self,
        address: MDataAddress,
        user: PublicKey,
    ) -> Box<CoreFuture<MDataPermissionSet>> {
        trace!("GetMDataUserPermissions for {:?}", address);

        send(self, Request::ListMDataUserPermissions { address, user })
            .and_then(|res| match res {
                Response::ListMDataUserPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Returns a list of values in an Unsequenced Mutable Data
    fn list_unseq_mdata_values(&self, name: XorName, tag: u64) -> Box<CoreFuture<Vec<Vec<u8>>>> {
        trace!("List MDataValues for {:?}", name);

        send(
            self,
            Request::ListMDataValues(MDataAddress::Unseq { name, tag }),
        )
        .and_then(|res| match res {
            Response::ListMDataValues(res) => {
                res.map_err(CoreError::from)
                    .and_then(|values| match values {
                        MDataValues::Unseq(data) => Ok(data),
                        MDataValues::Seq(_) => Err(CoreError::ReceivedUnexpectedData),
                    })
            }
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Return a list of permissions in `MutableData` stored on the network.
    fn list_mdata_permissions(
        &self,
        address: MDataAddress,
    ) -> Box<CoreFuture<BTreeMap<PublicKey, MDataPermissionSet>>> {
        trace!("List MDataPermissions for {:?}", address);

        send(self, Request::ListMDataPermissions(address))
            .and_then(|res| match res {
                Response::ListMDataPermissions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Updates or inserts a permissions set for a user
    fn set_mdata_user_permissions(
        &self,
        address: MDataAddress,
        user: PublicKey,
        permissions: MDataPermissionSet,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("SetMDataUserPermissions for {:?}", address);

        send_mutation(
            self,
            Request::SetMDataUserPermissions {
                address,
                user,
                permissions,
                version,
            },
        )
    }

    /// Updates or inserts a permissions set for a user
    fn del_mdata_user_permissions(
        &self,
        address: MDataAddress,
        user: PublicKey,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("DelMDataUserPermissions for {:?}", address);

        send_mutation(
            self,
            Request::DelMDataUserPermissions {
                address,
                user,
                version,
            },
        )
    }

    /// Sends an ownership transfer request.
    #[allow(unused)]
    fn change_mdata_owner(
        &self,
        name: XorName,
        tag: u64,
        new_owner: PublicKey,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        unimplemented!();
    }

    // ======= Sequence =======
    //
    /// Put Sequence into the Network
    fn put_sequence(&self, data: Sequence) -> Box<CoreFuture<()>> {
        trace!("Put Sequence {:?}", data.name());
        send_mutation(self, Request::PutSequence(data))
    }

    /// Get Sequence from the Network
    fn get_sequence(&self, address: Address) -> Box<CoreFuture<Sequence>> {
        trace!("Get Sequence at {:?}", address.name());

        send(self, Request::GetSequence(address))
            .and_then(|res| match res {
                Response::GetSequence(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Get Sequence Shell from the Network
    fn get_sequence_shell(
        &self,
        data_version: Option<Version>,
        address: Address,
    ) -> Box<CoreFuture<Sequence>> {
        trace!("Get Sequence at {:?}", address.name());

        send(
            self,
            Request::GetSequenceShell {
                address,
                data_version,
            },
        )
        .and_then(|res| match res {
            Response::GetSequenceShell(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Fetch Value for the provided version from Sequence at {:?}
    fn get_sequence_value(&self, address: Address, version: Version) -> Box<CoreFuture<Value>> {
        trace!(
            "Fetch Value for the provided key from Sequence at {:?}",
            address.name()
        );

        send(self, Request::GetSequenceValue { address, version })
            .and_then(|res| match res {
                Response::GetSequenceValue(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Get a Set of Entries for the requested range from an AData.
    fn get_sequence_range(
        &self,
        address: Address,
        range: (Version, Version),
    ) -> Box<CoreFuture<Values>> {
        trace!("Get Range of entries from Sequence at {:?}", address.name());

        send(self, Request::GetSequenceRange { address, range })
            .and_then(|res| match res {
                Response::GetSequenceRange(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Get expected versions from an Sequence.
    fn get_sequence_indices(&self, address: Address) -> Box<CoreFuture<ExpectedVersions>> {
        trace!("Get expected versions of Sequence at {:?}", address.name());

        send(self, Request::GetSequenceExpectedVersions(address))
            .and_then(|res| match res {
                Response::GetSequenceExpectedVersions(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Get the current data entry from a Sequence.
    fn get_sequence_current_entry(&self, address: Address) -> Box<CoreFuture<SequenceEntry>> {
        trace!("Get current entry from Sequence at {:?}", address.name());

        send(self, Request::GetSequenceCurrentEntry(address))
            .and_then(|res| match res {
                Response::GetSequenceCurrentEntry(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Get access list at the provided version.
    fn get_private_sequence_access_list_at_index(
        &self,
        address: Address,
        version: Version,
    ) -> Box<CoreFuture<PrivateAccessList>> {
        trace!("Get latest indices from Sequence at {:?}", address.name());

        send(self, Request::GetSequenceAccessListAt { address, version })
            .and_then(|res| match res {
                Response::GetSequenceAccessListAt(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|permissions| match permissions {
                            AccessList::Private(data) => Ok(data),
                            AccessList::Public(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Get access list at the provided version.
    fn get_public_sequence_access_list_at_index(
        &self,
        address: Address,
        version: Version,
    ) -> Box<CoreFuture<PublicAccessList>> {
        trace!("Get latest indices from Sequence at {:?}", address.name());

        send(self, Request::GetSequenceAccessListAt { address, version })
            .and_then(|res| match res {
                Response::GetSequenceAccessListAt(res) => {
                    res.map_err(CoreError::from)
                        .and_then(|permissions| match permissions {
                            AccessList::Public(data) => Ok(data),
                            AccessList::Private(_) => Err(CoreError::ReceivedUnexpectedData),
                        })
                }
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Get permissions for the specified user(s).
    fn get_public_sequence_user_permissions(
        &self,
        address: Address,
        version: Version,
        user: User,
    ) -> Box<CoreFuture<PublicUserAccess>> {
        trace!(
            "Get permissions for the specified user(s) from Sequence at {:?}",
            address.name()
        );

        send(
            self,
            Request::GetPublicSequenceUserPermissionsAt {
                address,
                version,
                user,
            },
        )
        .and_then(|res| match res {
            Response::GetPublicSequenceUserPermissionsAt(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Get permissions for the specified user(s).
    fn get_private_sequence_user_permissions(
        &self,
        address: Address,
        version: Version,
        public_key: PublicKey,
    ) -> Box<CoreFuture<PrivateUserAccess>> {
        trace!(
            "Get permissions for the specified user(s) from Sequence at {:?}",
            address.name()
        );

        send(
            self,
            Request::GetPrivateSequenceUserPermissionsAt {
                address,
                version,
                public_key,
            },
        )
        .and_then(|res| match res {
            Response::GetPrivateSequenceUserPermissionsAt(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::ReceivedUnexpectedEvent),
        })
        .into_box()
    }

    /// Set Sequence access list
    fn set_private_sequence_access_list(
        &self,
        address: Address,
        access_list: PrivateAccessList,
        expected_version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("Set Private Sequence access list {:?}", address.name());

        send_mutation(
            self,
            Request::SetPrivateSequenceAccessList {
                address,
                access_list,
                expected_version,
            },
        )
    }

    /// Set Public Sequence access list
    fn set_public_sequence_access_list(
        &self,
        address: Address,
        access_list: PublicAccessList,
        expected_version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("Set Sequence access list {:?}", address.name());

        send_mutation(
            self,
            Request::SetPublicSequenceAccessList {
                address,
                access_list,
                expected_version,
            },
        )
    }

    /// Set new Owner of Sequence
    fn set_sequence_owner(
        &self,
        address: Address,
        owner: Owner,
        expected_version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("Set Owner of Sequence {:?}", address.name());

        send_mutation(
            self,
            Request::SetSequenceOwner {
                address,
                owner,
                expected_version,
            },
        )
    }

    /// Get Sequence Owner
    fn get_sequence_owner(&self, address: Address, version: Version) -> Box<CoreFuture<Owner>> {
        trace!("Get Owner from Sequence at {:?}", address.name());

        send(self, Request::GetSequenceOwnerAt { address, version })
            .and_then(|res| match res {
                Response::GetSequenceOwnerAt(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Append to Public Sequence
    fn append(&self, append: AppendOperation) -> Box<CoreFuture<()>> {
        send_mutation(self, Request::Append(append))
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn set_network_limits(&self, max_ops_count: Option<u64>) {
        let inner = self.inner();
        inner
            .borrow_mut()
            .connection_manager
            .set_network_limits(max_ops_count);
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn simulate_network_disconnect(&self) {
        let inner = self.inner();
        inner.borrow_mut().connection_manager.simulate_disconnect();
    }

    #[cfg(any(
        all(test, feature = "mock-network"),
        all(feature = "testing", feature = "mock-network")
    ))]
    #[doc(hidden)]
    fn set_simulate_timeout(&self, enabled: bool) {
        let inner = self.inner();
        inner
            .borrow_mut()
            .connection_manager
            .set_simulate_timeout(enabled);
    }

    /// Set the coin balance to a specific value for testing
    #[cfg(any(test, feature = "testing"))]
    fn test_set_balance(
        &self,
        client_id: Option<&ClientFullId>,
        amount: Coins,
    ) -> Box<CoreFuture<Transaction>> {
        let new_balance_owner = client_id.map_or_else(
            || self.public_key(),
            |client_id| *client_id.public_id().public_key(),
        );
        trace!(
            "Set the coin balance of {:?} to {:?}",
            new_balance_owner,
            amount,
        );

        send_as!(
            self,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: rand::random(),
            },
            Response::Transaction,
            client_id
        )
    }
}

/// Creates a throw-away client to execute requests sequentially.
/// This function is blocking.
fn temp_client<F, R>(identity: &ClientFullId, mut func: F) -> Result<R, CoreError>
where
    F: FnMut(&mut ConnectionManager, &SafeKey) -> Result<R, CoreError>,
{
    let full_id = SafeKey::client(identity.clone());
    let (net_tx, _net_rx) = mpsc::unbounded();

    let mut cm = ConnectionManager::new(Config::new().quic_p2p, &net_tx)?;
    block_on_all(cm.bootstrap(full_id.clone()).map_err(CoreError::from))?;

    let res = func(&mut cm, &full_id);

    block_on_all(cm.disconnect(&full_id.public_id()))?;

    res
}

/// Create a new mock balance at an arbitrary address.
pub fn test_create_balance(owner: &ClientFullId, amount: Coins) -> Result<(), CoreError> {
    trace!("Create test balance of {} for {:?}", amount, owner);

    temp_client(owner, move |mut cm, full_id| {
        // Create the balance for the client
        let new_balance_owner = match full_id.public_id() {
            PublicId::Client(id) => *id.public_key(),
            x => return Err(CoreError::from(format!("Unexpected ID type {:?}", x))),
        };

        let response = req(
            &mut cm,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id: rand::random(),
            },
            &full_id,
        )?;

        match response {
            Response::Transaction(res) => res.map(|_| Ok(()))?,
            _ => Err(CoreError::from("Unexpected response")),
        }
    })
}

/// Get the balance at the given key's location
pub fn wallet_get_balance(wallet_sk: &ClientFullId) -> Result<Coins, CoreError> {
    trace!("Get balance for {:?}", wallet_sk);

    temp_client(wallet_sk, move |mut cm, full_id| {
        match req(&mut cm, Request::GetBalance, &full_id)? {
            Response::GetBalance(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response")),
        }
    })
}

/// Creates a new coin balance on the network.
pub fn wallet_create_balance(
    client_id: &ClientFullId,
    new_balance_owner: PublicKey,
    amount: Coins,
    transaction_id: Option<u64>,
) -> Result<Transaction, CoreError> {
    trace!(
        "Create a new coin balance for {:?} with {} coins.",
        new_balance_owner,
        amount
    );

    let transaction_id = transaction_id.unwrap_or_else(rand::random);

    temp_client(client_id, move |mut cm, full_id| {
        let response = req(
            &mut cm,
            Request::CreateBalance {
                new_balance_owner,
                amount,
                transaction_id,
            },
            &full_id,
        )?;
        match response {
            Response::Transaction(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response")),
        }
    })
}

/// Transfer coins
pub fn wallet_transfer_coins(
    client_id: &ClientFullId,
    destination: XorName,
    amount: Coins,
    transaction_id: Option<u64>,
) -> Result<Transaction, CoreError> {
    trace!("Transfer {} coins to {:?}", amount, destination);

    let transaction_id = transaction_id.unwrap_or_else(rand::random);

    temp_client(client_id, move |mut cm, full_id| {
        let response = req(
            &mut cm,
            Request::TransferCoins {
                destination,
                amount,
                transaction_id,
            },
            &full_id,
        )?;
        match response {
            Response::Transaction(res) => res.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response")),
        }
    })
}

/// This trait implements functions that are supposed to be called only by `CoreClient` and `AuthClient`.
/// Applications are not allowed to `DELETE MData` and get/mutate auth keys, hence `AppClient` does not implement
/// this trait.
pub trait AuthActions: Client + Clone + 'static {
    /// Fetches a list of authorised keys and version.
    fn list_auth_keys_and_version(
        &self,
    ) -> Box<CoreFuture<(BTreeMap<PublicKey, AppPermissions>, u64)>> {
        trace!("ListAuthKeysAndVersion");

        send(self, Request::ListAuthKeysAndVersion)
            .and_then(|res| match res {
                Response::ListAuthKeysAndVersion(res) => res.map_err(CoreError::from),
                _ => Err(CoreError::ReceivedUnexpectedEvent),
            })
            .into_box()
    }

    /// Adds a new authorised key.
    fn ins_auth_key(
        &self,
        key: PublicKey,
        permissions: AppPermissions,
        version: u64,
    ) -> Box<CoreFuture<()>> {
        trace!("InsAuthKey ({:?})", key);

        send_mutation(
            self,
            Request::InsAuthKey {
                key,
                permissions,
                version,
            },
        )
    }

    /// Removes an authorised key.
    fn del_auth_key(&self, key: PublicKey, version: u64) -> Box<CoreFuture<()>> {
        trace!("DelAuthKey ({:?})", key);

        send_mutation(self, Request::DelAuthKey { key, version })
    }

    /// Delete MData from network
    fn delete_mdata(&self, address: MDataAddress) -> Box<CoreFuture<()>> {
        trace!("Delete entire Mutable Data at {:?}", address);

        send_mutation(self, Request::DeleteMData(address))
    }

    /// Delete Sequence instance from network.
    fn delete_private_sequence(&self, address: Address) -> Box<CoreFuture<()>> {
        trace!("Delete Private Sequence instance at {:?}", address);

        send_mutation(self, Request::DeletePrivateSequence(address))
    }
}

fn sign_request(request: Request, client_id: &ClientFullId) -> Message {
    let message_id = MessageId::new();

    let signature = Some(client_id.sign(&unwrap!(bincode::serialize(&(&request, message_id)))));

    Message::Request {
        request,
        message_id,
        signature,
    }
}

// TODO: Consider deprecating this struct once trait fields are stable. See
// https://github.com/nikomatsakis/fields-in-traits-rfc.
/// Struct containing fields expected by the `Client` trait. Implementers of `Client` should be
/// composed around this struct.
#[allow(unused)] // FIXME
pub struct Inner<C: Client, T> {
    connection_manager: ConnectionManager,
    el_handle: Handle,
    cache: LruCache<IDataAddress, IData>,
    timeout: Duration,
    core_tx: CoreMsgTx<C, T>,
    net_tx: NetworkTx,
}

impl<C: Client, T> Inner<C, T> {
    /// Create a new `ClientInner` object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        el_handle: Handle,
        connection_manager: ConnectionManager,
        cache: LruCache<IDataAddress, IData>,
        timeout: Duration,
        core_tx: CoreMsgTx<C, T>,
        net_tx: NetworkTx,
    ) -> Inner<C, T> {
        Self {
            el_handle,
            connection_manager,
            cache,
            timeout,
            core_tx,
            net_tx,
        }
    }

    /// Get the connection manager associated with the client
    pub fn cm(&mut self) -> &mut ConnectionManager {
        &mut self.connection_manager
    }
}

/// Send a request and wait for a response.
/// This function is blocking.
pub fn req(
    cm: &mut ConnectionManager,
    request: Request,
    full_id_new: &SafeKey,
) -> Result<Response, CoreError> {
    let message_id = MessageId::new();
    let signature = full_id_new.sign(&unwrap!(bincode::serialize(&(&request, message_id))));

    block_on_all(cm.send(
        &full_id_new.public_id(),
        &Message::Request {
            request,
            message_id,
            signature: Some(signature),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::generate_random_vector;
    use crate::utils::test_utils::{
        calculate_new_balance, gen_bls_keypair, gen_client_id, random_client,
    };
    use safe_nd::{
        AccessType, Coins, Error as SndError, MDataAction, MDataKind, Owner, PrivateAccessList,
        PrivateSequence, PrivateUserAccess, PubImmutableData, PublicSequence, Scope, Sequence,
        UnpubImmutableData, XorName,
    };
    use std::str::FromStr;

    // Test putting and getting pub idata.
    #[test]
    fn pub_idata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            // The `random_client()` initializes the client with 10 coins.
            let start_bal = unwrap!(Coins::from_str("10"));

            let value = unwrap!(generate_random_vector::<u8>(10));
            let data = PubImmutableData::new(value.clone());
            let address = *data.address();
            let pk = gen_bls_keypair().public_key();

            let test_data = UnpubImmutableData::new(value, pk);
            client
                // Get inexistent idata
                .get_idata(address)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(data) => panic!("Pub idata should not exist yet: {:?}", data),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Put idata
                    client2.put_idata(data.clone())
                })
                .and_then(move |_| {
                    client3.put_idata(test_data.clone()).then(|res| match res {
                        Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                        Err(CoreError::DataError(SndError::InvalidOwners)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    })
                })
                .and_then(move |_| client4.get_balance(None))
                .and_then(move |balance| {
                    let expected_bal = calculate_new_balance(start_bal, Some(2), None);
                    assert_eq!(balance, expected_bal);
                    Ok(())
                })
                .and_then(move |_| {
                    // Fetch idata
                    client5.get_idata(address).map(move |fetched_data| {
                        assert_eq!(*fetched_data.address(), address);
                    })
                })
        })
    }

    // Test putting, getting, and deleting unpub idata.
    #[test]
    fn unpub_idata_test() {
        // The `random_client()` initializes the client with 10 coins.
        let start_bal = unwrap!(Coins::from_str("10"));

        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();
            let client8 = client.clone();
            let client9 = client.clone();

            let value = unwrap!(generate_random_vector::<u8>(10));
            let data = UnpubImmutableData::new(value.clone(), client.public_key());
            let data2 = data.clone();
            let data3 = data.clone();
            let address = *data.address();
            assert_eq!(address, *data2.address());

            let pub_data = PubImmutableData::new(value);

            client
                // Get inexistent idata
                .get_idata(address)
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Unpub idata should not exist yet"),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Put idata
                    client2.put_idata(data.clone())
                })
                .and_then(move |_| {
                    // Test putting unpub idata with the same value.
                    // Should conflict because duplication does not apply to unpublished data.
                    client3.put_idata(data2.clone())
                })
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Err(CoreError::DataError(SndError::DataExists)) => Ok(()),
                        res => panic!("Unexpected: {:?}", res),
                    }
                })
                .and_then(move |_| client4.get_balance(None))
                .and_then(move |balance| {
                    let expected_bal = calculate_new_balance(start_bal, Some(2), None);
                    assert_eq!(balance, expected_bal);
                    Ok(())
                })
                .and_then(move |_| {
                    // Test putting published idata with the same value. Should not conflict.
                    client5.put_idata(pub_data)
                })
                .and_then(move |_| {
                    // Fetch idata
                    client6.get_idata(address).map(move |fetched_data| {
                        assert_eq!(*fetched_data.address(), address);
                    })
                })
                .and_then(move |()| {
                    // Delete idata
                    client7.del_unpub_idata(*address.name())
                })
                .and_then(move |()| {
                    // Make sure idata was deleted
                    client8.get_idata(address)
                })
                .then(|res| -> Result<(), CoreError> {
                    match res {
                        Ok(_) => panic!("Unpub idata still exists after deletion"),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected: {:?}", e),
                    }
                })
                .and_then(move |_| {
                    // Test putting unpub idata with the same value again. Should not conflict.
                    client9.put_idata(data3.clone())
                })
        });
    }

    // 1. Create unseq. mdata with some entries and perms and put it on the network
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[test]
    pub fn unseq_mdata_test() {
        let _ = random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();

            let name = XorName(rand::random());
            let tag = 15001;
            let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new().allow(MDataAction::Read);
            let _ = permissions.insert(client.public_key(), permission_set);
            let _ = entries.insert(b"key".to_vec(), b"value".to_vec());
            let entries_keys = entries.keys().cloned().collect();
            let entries_values: Vec<Vec<u8>> = entries.values().cloned().collect();

            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );
            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put unseq. MData successfully");

                    client3
                        .get_mdata_version(MDataAddress::Unseq { name, tag })
                        .map(move |version| assert_eq!(version, 0))
                })
                .and_then(move |_| {
                    client4
                        .list_unseq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    client5
                        .list_mdata_keys(MDataAddress::Unseq { name, tag })
                        .map(move |keys| assert_eq!(keys, entries_keys))
                })
                .and_then(move |_| {
                    client6
                        .list_unseq_mdata_values(name, tag)
                        .map(move |values| assert_eq!(values, entries_values))
                })
                .and_then(move |_| {
                    client2
                        .get_unseq_mdata(*data.name(), data.tag())
                        .map(move |fetched_data| {
                            assert_eq!(fetched_data.name(), data.name());
                            assert_eq!(fetched_data.tag(), data.tag());
                            fetched_data
                        })
                })
                .then(|res| res)
        });
    }

    // 1. Create an put seq. mdata on the network with some entries and permissions.
    // 2. Fetch the shell version, entries, keys, values anv verify them
    // 3. Fetch the entire. data object and verify
    #[test]
    pub fn seq_mdata_test() {
        let _ = random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();

            let name = XorName(rand::random());
            let tag = 15001;
            let mut entries: MDataSeqEntries = Default::default();
            let _ = entries.insert(
                b"key".to_vec(),
                MDataSeqValue {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let entries_keys = entries.keys().cloned().collect();
            let entries_values: Vec<MDataSeqValue> = entries.values().cloned().collect();
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new().allow(MDataAction::Read);
            let _ = permissions.insert(client.public_key(), permission_set);
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );

            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |_| {
                    println!("Put seq. MData successfully");

                    client4
                        .list_seq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    client3
                        .get_seq_mdata_shell(name, tag)
                        .map(move |mdata_shell| {
                            assert_eq!(*mdata_shell.name(), name);
                            assert_eq!(mdata_shell.tag(), tag);
                            assert_eq!(mdata_shell.entries().len(), 0);
                        })
                })
                .and_then(move |_| {
                    client5
                        .list_mdata_keys(MDataAddress::Seq { name, tag })
                        .map(move |keys| assert_eq!(keys, entries_keys))
                })
                .and_then(move |_| {
                    client6
                        .list_seq_mdata_values(name, tag)
                        .map(move |values| assert_eq!(values, entries_values))
                })
                .and_then(move |_| {
                    client2.get_seq_mdata(name, tag).map(move |fetched_data| {
                        assert_eq!(fetched_data.name(), data.name());
                        assert_eq!(fetched_data.tag(), data.tag());
                        assert_eq!(fetched_data.entries().len(), 1);
                        fetched_data
                    })
                })
                .then(|res| res)
        });
    }

    // 1. Put seq. mdata on the network and then delete it
    // 2. Try getting the data object. It should panic
    #[test]
    pub fn del_seq_mdata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mdataref = MDataAddress::Seq { name, tag };
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                Default::default(),
                client.public_key(),
            );

            client
                .put_seq_mutable_data(data.clone())
                .and_then(move |_| {
                    client2.delete_mdata(mdataref).then(move |result| {
                        assert!(result.is_ok());
                        Ok(())
                    })
                })
                .then(move |_| {
                    client3
                        .get_unseq_mdata(*data.name(), data.tag())
                        .then(move |res| {
                            match res {
                                Err(CoreError::DataError(SndError::NoSuchData)) => (),
                                _ => panic!("Unexpected success"),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });
    }

    // 1. Put unseq. mdata on the network and then delete it
    // 2. Try getting the data object. It should panic
    #[test]
    pub fn del_unseq_mdata_test() {
        random_client(move |client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mdataref = MDataAddress::Unseq { name, tag };
            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                Default::default(),
                client.public_key(),
            );

            client
                .put_unseq_mutable_data(data.clone())
                .and_then(move |_| {
                    client2.delete_mdata(mdataref).then(move |result| {
                        assert!(result.is_ok());
                        Ok(())
                    })
                })
                .then(move |_| {
                    client3
                        .get_unseq_mdata(*data.name(), data.tag())
                        .then(move |res| {
                            match res {
                                Err(CoreError::DataError(SndError::NoSuchData)) => (),
                                _ => panic!("Unexpected success"),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });
    }

    // 1. Create 2 accounts and create a wallet only for account A.
    // 2. Try to transfer coins from A to inexistent wallet. This request should fail.
    // 3. Try to request balance of wallet B. This request should fail.
    // 4. Now create a wallet for account B and transfer some coins to A. This should pass.
    // 5. Try to request transaction from wallet A using account B. This request should succeed
    // (because transactions are always open).
    #[test]
    fn coin_permissions() {
        let wallet_a_addr = random_client(move |client| {
            let wallet_a_addr: XorName = client.public_key().into();
            client
                .transfer_coins(None, rand::random(), unwrap!(Coins::from_str("5.0")), None)
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::NoSuchBalance)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, SndError>(wallet_a_addr)
                })
        });

        random_client(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            client
                .get_balance(None)
                .then(move |res| {
                    // Subtract to cover the cost of inserting the login packet
                    let expected_amt = unwrap!(Coins::from_str("10")
                        .ok()
                        .and_then(|x| x.checked_sub(*COST_OF_PUT)));
                    match res {
                        Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    c2.test_set_balance(None, unwrap!(Coins::from_str("50.0")))
                })
                .and_then(move |_| {
                    c3.transfer_coins(None, wallet_a_addr, unwrap!(Coins::from_str("10")), None)
                })
                .then(move |res| {
                    match res {
                        Ok(transaction) => {
                            assert_eq!(transaction.amount, unwrap!(Coins::from_str("10")))
                        }
                        res => panic!("Unexpected error: {:?}", res),
                    }
                    c4.get_balance(None)
                })
                .then(move |res| {
                    let expected_amt = unwrap!(Coins::from_str("40"));
                    match res {
                        Ok(fetched_amt) => assert_eq!(expected_amt, fetched_amt),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, SndError>(())
                })
        });
    }

    // 1. Create a client with a wallet. Create an anonymous wallet preloading it from the client's wallet.
    // 2. Transfer some safecoin from the anonymous wallet to the client.
    // 3. Fetch the balances of both the wallets and verify them.
    // 5. Try to create a balance using an inexistent wallet. This should fail.
    #[test]
    fn anonymous_wallet() {
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let wallet1: XorName = client.owner_key().into();
            let init_bal = unwrap!(Coins::from_str("500.0"));

            let client_id = gen_client_id();
            let bls_pk = *client_id.public_id().public_key();

            client
                .test_set_balance(None, init_bal)
                .and_then(move |_| {
                    client1.create_balance(None, bls_pk, unwrap!(Coins::from_str("100.0")), None)
                })
                .and_then(move |transaction| {
                    assert_eq!(transaction.amount, unwrap!(Coins::from_str("100")));
                    client2
                        .transfer_coins(
                            Some(&client_id.clone()),
                            wallet1,
                            unwrap!(Coins::from_str("5.0")),
                            None,
                        )
                        .map(|transaction| (transaction, client_id))
                })
                .and_then(move |(transaction, client_id)| {
                    assert_eq!(transaction.amount, unwrap!(Coins::from_str("5.0")));
                    client3.get_balance(Some(&client_id)).and_then(|balance| {
                        assert_eq!(balance, unwrap!(Coins::from_str("95.0")));
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    client4.get_balance(None).and_then(move |balance| {
                        let expected = calculate_new_balance(
                            init_bal,
                            Some(1),
                            Some(unwrap!(Coins::from_str("95"))),
                        );
                        assert_eq!(balance, expected);
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    let random_pk = gen_bls_keypair().public_key();
                    let random_source = gen_client_id();

                    client5
                        .create_balance(
                            Some(&random_source),
                            random_pk,
                            unwrap!(Coins::from_str("100.0")),
                            None,
                        )
                        .then(|res| {
                            match res {
                                Err(CoreError::DataError(SndError::NoSuchBalance)) => {}
                                res => panic!("Unexpected result: {:?}", res),
                            }
                            Ok(())
                        })
                })
        });
    }

    // 1. Create a client A with a wallet and allocate some test safecoin to it.
    // 2. Get the balance and verify it.
    // 3. Create another client B with a wallet holding some safecoin.
    // 4. Transfer some coins from client B to client A and verify the new balance.
    // 5. Fetch the transaction using the transaction ID and verify the amount.
    // 6. Try to do a coin transfer without enough funds, it should return `InsufficientBalance`
    // 7. Try to do a coin transfer with the amount set to 0, it should return `InvalidOperation`
    // 8. Set the client's balance to zero and try to put data. It should fail.
    #[test]
    fn coin_balance_transfer() {
        let wallet1: XorName = random_client(move |client| {
            let client1 = client.clone();
            let owner_key = client.owner_key();
            let wallet1: XorName = owner_key.into();

            client
                .test_set_balance(None, unwrap!(Coins::from_str("100.0")))
                .and_then(move |_| client1.get_balance(None))
                .and_then(move |balance| {
                    assert_eq!(balance, unwrap!(Coins::from_str("100.0")));
                    Ok(wallet1)
                })
        });

        random_client(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();
            let c7 = client.clone();
            let c8 = client.clone();
            let init_bal = unwrap!(Coins::from_str("10"));
            client
                .get_balance(None)
                .and_then(move |orig_balance| {
                    c2.transfer_coins(None, wallet1, unwrap!(Coins::from_str("5.0")), None)
                        .map(move |_| orig_balance)
                })
                .and_then(move |orig_balance| {
                    c3.get_balance(None)
                        .map(move |new_balance| (new_balance, orig_balance))
                })
                .and_then(move |(new_balance, orig_balance)| {
                    assert_eq!(
                        new_balance,
                        unwrap!(orig_balance.checked_sub(unwrap!(Coins::from_str("5.0")))),
                    );
                    c4.transfer_coins(None, wallet1, unwrap!(Coins::from_str("5000")), None)
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok(())
                })
                // Check if coins are refunded
                .and_then(move |_| c5.get_balance(None))
                .and_then(move |balance| {
                    let expected = calculate_new_balance(
                        init_bal,
                        Some(1),
                        Some(unwrap!(Coins::from_str("5"))),
                    );
                    assert_eq!(balance, expected);
                    c6.transfer_coins(None, wallet1, unwrap!(Coins::from_str("0")), None)
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::InvalidOperation)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    c7.test_set_balance(None, unwrap!(Coins::from_str("0")))
                })
                .and_then(move |_| {
                    let data = PubImmutableData::new(unwrap!(generate_random_vector::<u8>(10)));
                    c8.put_idata(data)
                })
                .then(move |res| {
                    match res {
                        Err(CoreError::DataError(SndError::InsufficientBalance)) => (),
                        res => panic!("Unexpected result: {:?}", res),
                    }
                    Ok::<_, SndError>(())
                })
        });
    }

    // 1. Create a client that PUTs some mdata on the network
    // 2. Create a different client that tries to delete the data. It should panic.
    #[test]
    pub fn del_unseq_mdata_permission_test() {
        let name = XorName(rand::random());
        let tag = 15001;
        let mdataref = MDataAddress::Unseq { name, tag };

        random_client(move |client| {
            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                Default::default(),
                client.public_key(),
            );

            client.put_unseq_mutable_data(data).then(|res| res)
        });

        random_client(move |client| {
            client.delete_mdata(mdataref).then(|res| {
                match res {
                    Err(CoreError::DataError(SndError::AccessDenied)) => (),
                    res => panic!("Unexpected result: {:?}", res),
                }
                Ok::<_, SndError>(())
            })
        });
    }

    // 1. Create a mutable data with some permissions and store it on the network.
    // 2. Modify the permissions of a user in the permission set.
    // 3. Fetch the list of permissions and verify the edit.
    // 4. Delete a user's permissions from the permission set and verify the deletion.
    #[test]
    pub fn mdata_permissions_test() {
        random_client(|client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            // The `random_client()` initializes the client with 10 coins.
            let start_bal = unwrap!(Coins::from_str("10"));
            let name = XorName(rand::random());
            let tag = 15001;
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::ManagePermissions);
            let user = client.public_key();
            let user2 = user;
            let random_user = gen_bls_keypair().public_key();
            let random_pk = gen_bls_keypair().public_key();

            let _ = permissions.insert(user, permission_set.clone());
            let _ = permissions.insert(random_user, permission_set);

            let data = SeqMutableData::new_with_data(
                name,
                tag,
                Default::default(),
                permissions.clone(),
                client.public_key(),
            );
            let test_data = SeqMutableData::new_with_data(
                XorName(rand::random()),
                15000,
                Default::default(),
                permissions,
                random_pk,
            );

            client
                .put_seq_mutable_data(data)
                .then(move |res| {
                    assert!(res.is_ok());
                    Ok(())
                })
                .and_then(move |_| {
                    client1
                        .put_seq_mutable_data(test_data.clone())
                        .then(|res| match res {
                            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                            Err(CoreError::DataError(SndError::InvalidOwners)) => Ok(()),
                            Err(e) => panic!("Unexpected: {:?}", e),
                        })
                })
                // Check if coins are refunded
                .and_then(move |_| client2.get_balance(None))
                .and_then(move |balance| {
                    let expected_bal = calculate_new_balance(start_bal, Some(2), None);
                    assert_eq!(balance, expected_bal);
                    Ok(())
                })
                .and_then(move |_| {
                    let new_perm_set = MDataPermissionSet::new()
                        .allow(MDataAction::ManagePermissions)
                        .allow(MDataAction::Read);
                    client3
                        .set_mdata_user_permissions(
                            MDataAddress::Seq { name, tag },
                            user,
                            new_perm_set,
                            1,
                        )
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    println!("Modified user permissions");

                    client4
                        .list_mdata_user_permissions(MDataAddress::Seq { name, tag }, user2)
                        .and_then(|permissions| {
                            assert!(!permissions.is_allowed(MDataAction::Insert));
                            assert!(permissions.is_allowed(MDataAction::Read));
                            assert!(permissions.is_allowed(MDataAction::ManagePermissions));
                            println!("Verified new permissions");

                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client5
                        .del_mdata_user_permissions(MDataAddress::Seq { name, tag }, random_user, 2)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    println!("Deleted permissions");
                    client6
                        .list_mdata_permissions(MDataAddress::Seq { name, tag })
                        .and_then(|permissions| {
                            assert_eq!(permissions.len(), 1);
                            println!("Permission set verified");
                            Ok(())
                        })
                })
        })
    }

    // 1. Create a mutable data and store it on the network
    // 2. Create some entry actions and mutate the data on the network.
    // 3. List the entries and verify that the mutation was applied.
    // 4. Fetch a value for a particular key and verify
    #[test]
    pub fn mdata_mutations_test() {
        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete);
            let user = client.public_key();
            let _ = permissions.insert(user, permission_set);
            let mut entries: MDataSeqEntries = Default::default();
            let _ = entries.insert(
                b"key1".to_vec(),
                MDataSeqValue {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let _ = entries.insert(
                b"key2".to_vec(),
                MDataSeqValue {
                    data: b"value".to_vec(),
                    version: 0,
                },
            );
            let data = SeqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );
            client
                .put_seq_mutable_data(data)
                .and_then(move |_| {
                    println!("Put seq. MData successfully");

                    client2
                        .list_seq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    let entry_actions: MDataSeqEntryActions = MDataSeqEntryActions::new()
                        .update(b"key1".to_vec(), b"newValue".to_vec(), 1)
                        .del(b"key2".to_vec(), 1)
                        .ins(b"key3".to_vec(), b"value".to_vec(), 0);

                    client3
                        .mutate_seq_mdata_entries(name, tag, entry_actions)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client4
                        .list_seq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            let mut expected_entries: BTreeMap<_, _> = Default::default();
                            let _ = expected_entries.insert(
                                b"key1".to_vec(),
                                MDataSeqValue {
                                    data: b"newValue".to_vec(),
                                    version: 1,
                                },
                            );
                            let _ = expected_entries.insert(
                                b"key3".to_vec(),
                                MDataSeqValue {
                                    data: b"value".to_vec(),
                                    version: 0,
                                },
                            );
                            assert_eq!(fetched_entries, expected_entries);
                        })
                })
                .and_then(move |_| {
                    client5
                        .get_seq_mdata_value(name, tag, b"key3".to_vec())
                        .and_then(|fetched_value| {
                            assert_eq!(
                                fetched_value,
                                MDataSeqValue {
                                    data: b"value".to_vec(),
                                    version: 0
                                }
                            );
                            Ok(())
                        })
                })
                .then(move |_| {
                    client6
                        .get_seq_mdata_value(name, tag, b"wrongKey".to_vec())
                        .then(|res| {
                            match res {
                                Ok(_) => panic!("Unexpected: Entry should not exist"),
                                Err(CoreError::DataError(SndError::NoSuchEntry)) => (),
                                Err(err) => panic!("Unexpected error: {:?}", err),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });

        random_client(|client| {
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let name = XorName(rand::random());
            let tag = 15001;
            let mut permissions: BTreeMap<_, _> = Default::default();
            let permission_set = MDataPermissionSet::new()
                .allow(MDataAction::Read)
                .allow(MDataAction::Insert)
                .allow(MDataAction::Update)
                .allow(MDataAction::Delete);
            let user = client.public_key();
            let _ = permissions.insert(user, permission_set);
            let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
            let _ = entries.insert(b"key1".to_vec(), b"value".to_vec());
            let _ = entries.insert(b"key2".to_vec(), b"value".to_vec());
            let data = UnseqMutableData::new_with_data(
                name,
                tag,
                entries.clone(),
                permissions,
                client.public_key(),
            );
            client
                .put_unseq_mutable_data(data)
                .and_then(move |_| {
                    println!("Put unseq. MData successfully");

                    client2
                        .list_unseq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            assert_eq!(fetched_entries, entries);
                        })
                })
                .and_then(move |_| {
                    let entry_actions: MDataUnseqEntryActions = MDataUnseqEntryActions::new()
                        .update(b"key1".to_vec(), b"newValue".to_vec())
                        .del(b"key2".to_vec())
                        .ins(b"key3".to_vec(), b"value".to_vec());

                    client3
                        .mutate_unseq_mdata_entries(name, tag, entry_actions)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client4
                        .list_unseq_mdata_entries(name, tag)
                        .map(move |fetched_entries| {
                            let mut expected_entries: BTreeMap<_, _> = Default::default();
                            let _ = expected_entries.insert(b"key1".to_vec(), b"newValue".to_vec());
                            let _ = expected_entries.insert(b"key3".to_vec(), b"value".to_vec());
                            assert_eq!(fetched_entries, expected_entries);
                        })
                })
                .and_then(move |_| {
                    client5
                        .get_unseq_mdata_value(name, tag, b"key1".to_vec())
                        .and_then(|fetched_value| {
                            assert_eq!(fetched_value, b"newValue".to_vec());
                            Ok(())
                        })
                })
                .then(move |_| {
                    client6
                        .get_unseq_mdata_value(name, tag, b"wrongKey".to_vec())
                        .then(|res| {
                            match res {
                                Ok(_) => panic!("Unexpected: Entry should not exist"),
                                Err(CoreError::DataError(SndError::NoSuchEntry)) => (),
                                Err(err) => panic!("Unexpected error: {:?}", err),
                            }
                            Ok::<_, SndError>(())
                        })
                })
        });
    }

    #[test]
    pub fn adata_basics_test() {
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();

            let name = XorName(rand::random());
            let tag = 15000;
            let mut data = PrivateSequence::new(name, tag);
            let mut perms = BTreeMap::<PublicKey, PrivateUserAccess>::new();
            let mut permissions = BTreeSet::new();
            let _ = permissions.insert(AccessType::Read);
            let _ = permissions.insert(AccessType::Append);
            let _ = permissions.insert(AccessType::ModifyPermissions);
            let user_access = PrivateUserAccess::new(permissions);
            //let data_version = Version::FromStart(0);
            let _ = perms.insert(client.public_key(), user_access);
            let address = Address::Private { name, tag };

            unwrap!(data.set_access_list(
                PrivateAccessList {
                    access_list: perms,
                    expected_data_version: 0,
                    expected_owners_version: 0,
                },
                0
            ));

            let owner = Owner {
                public_key: client.public_key(),
                expected_data_version: 0,
                expected_access_list_version: 1,
            };
            unwrap!(data.set_owner(owner, 0));

            client
                .put_sequence(Sequence::Private(data))
                .and_then(move |_| {
                    client1.get_sequence(address).map(move |data| match data {
                        Sequence::Private(adata) => assert_eq!(*adata.name(), name),
                        _ => panic!("Unexpected data found"),
                    })
                })
                .and_then(move |_| {
                    client2
                        .get_sequence_shell(None, address)
                        .map(move |data| match data {
                            Sequence::Private(adata) => {
                                assert_eq!(*adata.name(), name);
                                assert_eq!(adata.tag(), tag);
                                assert_eq!(adata.expected_access_list_version(), 1);
                                assert_eq!(adata.expected_owners_version(), 1);
                            }
                            _ => panic!("Unexpected data found"),
                        })
                })
                .and_then(move |_| client3.delete_private_sequence(address))
                .and_then(move |_| {
                    client4.get_sequence(address).then(|res| match res {
                        Ok(_) => panic!("AData was not deleted"),
                        Err(CoreError::DataError(SndError::NoSuchData)) => Ok(()),
                        Err(e) => panic!("Unexpected error: {:?}", e),
                    })
                })
                .then(move |res| res)
        });
    }

    #[test]
    pub fn adata_permissions_test() {
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();
            let client4 = client.clone();
            let client5 = client.clone();
            let client6 = client.clone();
            let client7 = client.clone();
            let client8 = client.clone();

            let name = XorName(rand::random());
            let tag = 15000;
            let adataref = Address::Private { name, tag };
            let mut data = PrivateSequence::new(name, tag);
            let mut perms = BTreeMap::<PublicKey, PrivateUserAccess>::new();
            let mut permissions = BTreeSet::new();
            let _ = permissions.insert(AccessType::Read);
            let _ = permissions.insert(AccessType::Append);
            let _ = permissions.insert(AccessType::ModifyPermissions);
            let user_access = PrivateUserAccess::new(permissions);

            let _ = perms.insert(client.public_key(), user_access);

            let key1 = b"KEY1".to_vec();
            let key2 = b"KEY2".to_vec();
            let key3 = b"KEY3".to_vec();
            let key4 = b"KEY4".to_vec();

            let val1 = b"VALUE1".to_vec();
            let val2 = b"VALUE2".to_vec();
            let val3 = b"VALUE3".to_vec();
            let val4 = b"VALUE4".to_vec();

            let kvdata = vec![key1, val1, key2, val2, key3, val3];

            unwrap!(data.append(kvdata, Some(0)));
            // Test push
            unwrap!(data.append(vec![key4, val4], Some(3)));

            unwrap!(data.set_access_list(
                PrivateAccessList {
                    access_list: perms,
                    expected_data_version: 4,
                    expected_owners_version: 0,
                },
                0
            ));

            let index_start = Version::FromStart(0);
            let index_end = Version::FromEnd(2);
            let perm_index = Version::FromStart(1);

            let sim_client = gen_bls_keypair().public_key();
            let sim_client1 = sim_client;

            let mut perms2 = BTreeMap::<PublicKey, PrivateUserAccess>::new();
            let mut permissions_2 = BTreeSet::new();
            let _ = permissions_2.insert(AccessType::Read);
            let _ = permissions_2.insert(AccessType::Append);
            let _ = permissions_2.insert(AccessType::ModifyPermissions);
            let user_access_2 = PrivateUserAccess::new(permissions_2);

            let _ = perms2.insert(sim_client, user_access_2);

            let perm_set = PrivateAccessList {
                access_list: perms2,
                expected_data_version: 4,
                expected_owners_version: 1,
            };

            let owner = Owner {
                public_key: client.public_key(),
                expected_data_version: 4,
                expected_access_list_version: 1,
            };

            unwrap!(data.set_owner(owner, 0));

            let mut test_data = PrivateSequence::new(XorName(rand::random()), 15000);
            let test_owner = Owner {
                public_key: gen_bls_keypair().public_key(),
                expected_data_version: 0,
                expected_access_list_version: 0,
            };

            unwrap!(test_data.set_owner(test_owner, 0));

            client
                .put_sequence(Sequence::Private(data))
                .then(move |res| {
                    assert!(res.is_ok());
                    Ok(())
                })
                .and_then(move |_| {
                    client1
                        .put_sequence(Sequence::Private(test_data.clone()))
                        .then(|res| match res {
                            Ok(_) => panic!("Unexpected Success: Validating owners should fail"),
                            Err(CoreError::DataError(SndError::InvalidOwners)) => Ok(()),
                            Err(e) => panic!("Unexpected: {:?}", e),
                        })
                })
                .and_then(move |_| {
                    client2
                        .get_sequence_range(adataref, (index_start, index_end))
                        .map(move |data| {
                            assert_eq!(
                                unwrap!(std::str::from_utf8(&unwrap!(data.last()))), // todo: fix
                                "KEY2"
                            );
                            assert_eq!(
                                unwrap!(std::str::from_utf8(&unwrap!(data.last()))), // todo: fix
                                "VALUE2"
                            );
                        })
                })
                .and_then(move |_| {
                    client3.get_sequence_indices(adataref).map(move |data| {
                        assert_eq!(data.data_version, 4);
                        assert_eq!(data.owners_version, 1);
                        assert_eq!(data.access_list_version, 1);
                    })
                })
                .and_then(move |_| {
                    client4
                        .get_sequence_value(adataref, Version::FromStart(0))
                        .map(move |data| {
                            assert_eq!(unwrap!(std::str::from_utf8(data.as_slice())), "VALUE1");
                            // todo: fix
                        })
                })
                .and_then(move |_| {
                    client5
                        .get_sequence_current_entry(adataref)
                        .map(move |data| {
                            assert_eq!(unwrap!(std::str::from_utf8(data.value.as_slice())), "KEY4"); // todo: fix
                            assert_eq!(
                                unwrap!(std::str::from_utf8(data.value.as_slice())),
                                "VALUE4"
                            );
                        })
                })
                .and_then(move |_| {
                    client6
                        .set_private_sequence_access_list(adataref, perm_set, 1)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client7
                        .get_private_sequence_access_list_at_index(adataref, perm_index)
                        .map(move |data| {
                            let set = unwrap!(data.access_list.get(&sim_client1));
                            assert!(set.is_allowed(AccessType::Append));
                        })
                })
                .and_then(move |_| {
                    client8
                        .get_private_sequence_user_permissions(
                            adataref,
                            index_start,
                            client8.public_key(),
                        )
                        .map(move |set| {
                            assert!(set.is_allowed(AccessType::Append));
                        })
                })
                .then(|res| res)
        });
    }

    #[test]
    pub fn append_test() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();

            let adataref = Address::Public { name, tag };
            let mut data = PublicSequence::new(name, tag);

            let mut perms = BTreeMap::<User, PublicUserAccess>::new();
            let mut permissions = BTreeMap::new();
            let _ = permissions.insert(AccessType::Append, true);
            let _ = permissions.insert(AccessType::ModifyPermissions, true);
            let user_access = PublicUserAccess::new(permissions);

            let user = User::Specific(client.public_key());
            let _ = perms.insert(user, user_access);

            unwrap!(data.set_access_list(
                PublicAccessList {
                    access_list: perms,
                    expected_data_version: 0,
                    expected_owners_version: 0,
                },
                0
            ));

            let key1 = b"KEY1".to_vec();
            let val1 = b"VALUE1".to_vec();
            let key2 = b"KEY2".to_vec();
            let val2 = b"VALUE2".to_vec();

            let values = vec![key1, val1, key2, val2];

            let append = AppendOperation::new(adataref, values, None); // Some(ExpectedVersion)

            let owner = Owner {
                public_key: client.public_key(),
                expected_data_version: 0,
                expected_access_list_version: 1,
            };

            unwrap!(data.set_owner(owner, 0));

            client
                .put_sequence(Sequence::Public(data))
                .and_then(move |_| {
                    client1.append(append).then(move |res| {
                        assert!(res.is_ok());
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    client2.get_sequence(adataref).map(move |data| match data {
                        Sequence::Public(adata) => assert_eq!(
                            unwrap!(std::str::from_utf8(
                                &unwrap!(adata.current_data_entry()).value
                            )), // todo: fix
                            "KEY2"
                        ),
                        _ => panic!("UNEXPECTED DATA!"),
                    })
                })
                .then(|res| res)
        });
    }

    #[test]
    pub fn append_test_0() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();

            let adataref = Address::Private { name, tag };
            let mut data = PrivateSequence::new(name, tag);

            let mut perms = BTreeMap::<PublicKey, PrivateUserAccess>::new();
            let mut permissions = BTreeSet::new();
            let _ = permissions.insert(AccessType::Read);
            let _ = permissions.insert(AccessType::Append);
            let _ = permissions.insert(AccessType::ModifyPermissions);
            let user_access = PrivateUserAccess::new(permissions);

            let _ = perms.insert(client.public_key(), user_access);

            unwrap!(data.set_access_list(
                PrivateAccessList {
                    access_list: perms,
                    expected_data_version: 0,
                    expected_owners_version: 0,
                },
                0
            ));

            let key1 = b"KEY1".to_vec();
            let val1 = b"VALUE1".to_vec();
            let key2 = b"KEY2".to_vec();
            let val2 = b"VALUE2".to_vec();

            let values = vec![key1, val1, key2, val2];

            let append = AppendOperation::new(adataref, values, None); // Some(ExpectedVersion)

            let owner = Owner {
                public_key: client.public_key(),
                expected_data_version: 0,
                expected_access_list_version: 1,
            };

            unwrap!(data.set_owner(owner, 0));

            client
                .put_sequence(Sequence::Private(data))
                .and_then(move |_| {
                    client1.append(append).then(move |res| {
                        assert!(res.is_ok());
                        Ok(())
                    })
                })
                .and_then(move |_| {
                    client2.get_sequence(adataref).map(move |data| match data {
                        Sequence::Private(adata) => assert_eq!(
                            unwrap!(std::str::from_utf8(
                                &unwrap!(adata.current_data_entry()).value
                            )), // todo: fix
                            "KEY2"
                        ),
                        _ => panic!("UNEXPECTED DATA!"),
                    })
                })
                .then(|res| res)
        });
    }

    #[test]
    pub fn set_and_get_owner_adata_test() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let client1 = client.clone();
            let client2 = client.clone();
            let client3 = client.clone();

            let adataref = Address::Private { name, tag };
            let mut data = PrivateSequence::new(name, tag);

            let mut perms = BTreeMap::<PublicKey, PrivateUserAccess>::new();
            let mut permissions = BTreeSet::new();
            let _ = permissions.insert(AccessType::Read);
            let _ = permissions.insert(AccessType::Append);
            let _ = permissions.insert(AccessType::ModifyPermissions);
            let user_access = PrivateUserAccess::new(permissions);

            let _ = perms.insert(client.public_key(), user_access);

            unwrap!(data.set_access_list(
                PrivateAccessList {
                    access_list: perms,
                    expected_data_version: 0,
                    expected_owners_version: 0,
                },
                0
            ));

            let key1 = b"KEY1".to_vec();
            let key2 = b"KEY2".to_vec();

            let val1 = b"VALUE1".to_vec();
            let val2 = b"VALUE2".to_vec();

            let kvdata = vec![key1, val1, key2, val2];

            unwrap!(data.append(kvdata, Some(0)));

            let owner = Owner {
                public_key: client.public_key(),
                expected_data_version: 2,
                expected_access_list_version: 1,
            };

            unwrap!(data.set_owner(owner, 0));

            let owner2 = Owner {
                public_key: client1.public_key(),
                expected_data_version: 2,
                expected_access_list_version: 1,
            };

            let owner3 = Owner {
                public_key: client2.public_key(),
                expected_data_version: 2,
                expected_access_list_version: 1,
            };

            client
                .put_sequence(Sequence::Private(data))
                .and_then(move |_| {
                    client1
                        .set_sequence_owner(adataref, owner2, 1)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client2
                        .set_sequence_owner(adataref, owner3, 2)
                        .then(move |res| {
                            assert!(res.is_ok());
                            Ok(())
                        })
                })
                .and_then(move |_| {
                    client3.get_sequence(adataref).map(move |data| match data {
                        Sequence::Private(adata) => assert_eq!(adata.expected_owners_version(), 3),
                        _ => panic!("UNEXPECTED DATA!"),
                    })
                })
                .then(|res| res)
        });
    }

    // 1. Create a random BLS key and create a wallet for it with some test safecoin.
    // 2. Without a client object, try to get the balance, create new wallets and transfer safecoin.
    #[test]
    pub fn wallet_transactions_without_client() {
        let client_id = gen_client_id();

        unwrap!(test_create_balance(
            &client_id,
            unwrap!(Coins::from_str("50"))
        ));

        let balance = unwrap!(wallet_get_balance(&client_id));
        let ten_coins = unwrap!(Coins::from_str("10"));
        assert_eq!(balance, unwrap!(Coins::from_str("50")));

        let new_client_id = gen_client_id();
        let new_client_pk = new_client_id.public_id().public_key();
        let new_wallet: XorName = *new_client_id.public_id().name();
        let txn = unwrap!(wallet_create_balance(
            &client_id,
            *new_client_pk,
            ten_coins,
            None
        ));
        assert_eq!(txn.amount, ten_coins);
        let txn2 = unwrap!(wallet_transfer_coins(
            &client_id, new_wallet, ten_coins, None
        ));
        assert_eq!(txn2.amount, ten_coins);

        let client_balance = unwrap!(wallet_get_balance(&client_id));
        let expected = unwrap!(Coins::from_str("30"));
        let expected = unwrap!(expected.checked_sub(*COST_OF_PUT));
        assert_eq!(client_balance, expected);

        let new_client_balance = unwrap!(wallet_get_balance(&new_client_id));
        assert_eq!(new_client_balance, unwrap!(Coins::from_str("20")));
    }

    // 1. Store different variants of unpublished data on the network.
    // 2. Get the balance of the client.
    // 3. Delete data from the network.
    // 4. Verify that the balance has not changed since deletions are free.
    #[test]
    pub fn deletions_should_be_free() {
        let name = XorName(rand::random());
        let tag = 10;
        random_client(move |client| {
            let c2 = client.clone();
            let c3 = client.clone();
            let c4 = client.clone();
            let c5 = client.clone();
            let c6 = client.clone();
            let c7 = client.clone();
            let c8 = client.clone();

            let idata = UnpubImmutableData::new(
                unwrap!(generate_random_vector::<u8>(10)),
                client.public_key(),
            );
            let address = *idata.name();
            client
                .put_idata(idata)
                .and_then(move |_| {
                    let mut adata = PrivateSequence::new(name, tag);
                    let owner = Owner {
                        public_key: c2.public_key(),
                        expected_data_version: 0,
                        expected_access_list_version: 0,
                    };
                    unwrap!(adata.set_owner(owner, 0));
                    c2.put_sequence(adata.into())
                })
                .and_then(move |_| {
                    let mdata = UnseqMutableData::new(name, tag, c3.public_key());
                    c3.put_unseq_mutable_data(mdata)
                })
                .and_then(move |_| c4.get_balance(None))
                .and_then(move |balance| {
                    c5.delete_private_sequence(Address::from_scope(Scope::Private, name, tag))
                        .map(move |_| balance)
                })
                .and_then(move |balance| {
                    c6.delete_mdata(MDataAddress::from_kind(MDataKind::Unseq, name, tag))
                        .map(move |_| balance)
                })
                .and_then(move |balance| c7.del_unpub_idata(address).map(move |_| balance))
                .and_then(move |balance| {
                    c8.get_balance(None)
                        .map(move |bal| assert_eq!(bal, balance))
                })
        });
    }
}
