use crate::connection_manager::STANDARD_ELDERS_COUNT;
use bincode::serialize;
use log::{debug, error, info, trace, warn};
use sn_data_types::{
    DebitId, Keypair, PublicKey, SignedTransfer, Token, TransferAgreementProof, TransferValidated,
};
use sn_messaging::client::{
    ClientMessage, Cmd, DataCmd, Query, QueryResponse, TransferCmd, TransferQuery,
};
use sn_transfers::{ActorEvent, ReplicaValidator, TransferInitiated};
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::channel;

/// Module for token balance management
pub mod balance_management;
/// Module for simulating token for testing
pub mod simulated_payouts;
/// Module containing all PUT apis
pub mod write_apis;

/// Actual Transfer Actor
pub use sn_transfers::TransferActor as SafeTransferActor;

use crate::client::{Client, ConnectionManager};
use crate::errors::Error;

/// Simple client side validations
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransferValidator {}

impl ReplicaValidator for ClientTransferValidator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}

impl Client {
    /// Get the client's current coin balance from the network
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Token};
    /// use rand::rngs::OsRng;
    /// use std::str::FromStr;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random id.
    /// // (It should have 0 balance)
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// let client = Client::new(Some(id), None).await?;
    /// let initial_balance = Token::from_str("0")?;
    /// let balance = client.get_balance().await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance(&self) -> Result<Token, Error>
    where
        Self: Sized,
    {
        trace!("Getting balance for {:?}", self.public_key().await);

        // we're a standard client grabbing our own key's balance
        self.get_balance_from_network(None).await
    }

    /// Get balance for a Public Key on the network.
    ///
    /// # Examples
    ///
    /// Retrieve an existing balance
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Token};
    /// use std::str::FromStr;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's check the balance of a client with a random id.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// let pk = id.public_key();
    ///
    /// // And we use a random client to do this
    /// let client = Client::new(None, None).await?;
    /// let initial_balance = Token::from_str("0")?;
    /// let balance = client.get_balance_for(pk).await?;
    /// assert_eq!(balance, initial_balance);
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_balance_for(&self, public_key: PublicKey) -> Result<Token, Error>
    where
        Self: Sized,
    {
        trace!("Get balance for {:?}", public_key);
        self.get_balance_from_network(Some(public_key)).await
    }

    /// Retrieve the history of the account from the network and apply to our local client's AT2 actor.
    ///
    /// # Examples
    ///
    /// Retrieving an existing balance history
    /// ```no_run
    /// # extern crate tokio; use sn_client::Error;
    /// use sn_client::Client;
    /// use sn_data_types::Keypair;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<(), Error> = futures::executor::block_on( async {
    /// // Let's check the balance of a random client.
    /// // And we use a random client id to do this
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// let client = Client::new(Some(id), None).await?;
    /// // Upon calling, history is retrieved and applied to the local AT2 actor.
    /// let _ = client.get_history().await?;
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_history(&self) -> Result<(), Error> {
        let public_key = self.public_key().await;
        info!("Getting SnTransfers history for pk: {:?}", public_key);

        let msg_contents = Query::Transfer(TransferQuery::GetHistory {
            at: public_key,
            since_version: 0,
        });

        let message = Self::create_query_message(msg_contents);

        // This is a normal response manager request. We want quorum on this for now...
        let res = self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?;

        let history = match res {
            QueryResponse::GetHistory(history) => history.map_err(Error::from),
            _ => Err(Error::UnexpectedHistoryResponse(res)),
        }?;

        let mut actor = self.transfer_actor.lock().await;
        match actor.from_history(history) {
            Ok(synced_transfer_outcome) => {
                if let Some(transfers) = synced_transfer_outcome {
                    actor.apply(ActorEvent::TransfersSynched(transfers))?;
                }
            }
            Err(error) => {
                if !error
                    .to_string()
                    .contains("No credits or debits found to sync to actor")
                {
                    return Err(Error::from(error));
                }

                warn!(
                    "No new transfer history  by TransferActor for pk: {:?}",
                    public_key
                );
            }
        }

        debug!("Current balance after GetHistory {:?}", actor.balance());

        Ok(())
    }

    /// Fetch latest StoreCost for given number of bytes from the network.
    pub async fn get_store_cost(&self, bytes: u64) -> Result<Token, Error> {
        info!("Sending Query for latest StoreCost");

        let public_key = self.public_key().await;

        let msg_contents = Query::Transfer(TransferQuery::GetStoreCost {
            requester: public_key,
            bytes,
        });

        let message = Self::create_query_message(msg_contents);

        // This is a normal response manager request. We want quorum on this for now...
        let res = self
            .connection_manager
            .lock()
            .await
            .send_query(&message)
            .await?;

        match res {
            QueryResponse::GetStoreCost(cost) => cost.map_err(Error::ErrorMessage),
            _ => Err(Error::UnexpectedStoreCostResponse(res)),
        }
    }

    /// Validates a transaction for paying store_cost
    pub(crate) async fn create_write_payment_proof(
        &self,
        cmd: &DataCmd,
    ) -> Result<TransferAgreementProof, Error> {
        info!("Sending requests for payment for write operation");

        // Compute number of bytes
        let bytes = serialize(cmd)?.len() as u64;

        self.get_history().await?;

        let section_key = PublicKey::Bls(self.replicas_pk_set.public_key());

        let cost_of_put = self.get_store_cost(bytes).await?;

        let initiated = self
            .transfer_actor
            .lock()
            .await
            .transfer(cost_of_put, section_key, "asdf".to_string())?
            .ok_or(Error::NoTransferEventsForLocalActor)?;
        let signed_transfer = SignedTransfer {
            debit: initiated.signed_debit,
            credit: initiated.signed_credit,
        };

        let command = Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer.clone()));

        debug!("Transfer to be sent: {:?}", &signed_transfer);

        let transfer_message = Self::create_cmd_message(command);

        self.transfer_actor
            .lock()
            .await
            .apply(ActorEvent::TransferInitiated(TransferInitiated {
                signed_debit: signed_transfer.debit.clone(),
                signed_credit: signed_transfer.credit.clone(),
            }))?;

        let payment_proof: TransferAgreementProof = self
            .await_validation(&transfer_message, signed_transfer.id())
            .await?;

        debug!("Payment proof retrieved");
        Ok(payment_proof)
    }

    /// Get our replica instance PK set
    pub(crate) async fn get_replica_keys(
        keypair: Keypair,
        cm: &mut ConnectionManager,
    ) -> Result<PublicKeySet, Error> {
        trace!("Getting replica keys for {:?}", keypair);
        let pk = keypair.public_key();
        let keys_query_msg = Query::Transfer(TransferQuery::GetReplicaKeys(pk));

        let message = Self::create_query_message(keys_query_msg);

        let res = cm.send_query(&message).await?;

        match res {
            QueryResponse::GetReplicaKeys(pk_set) => Ok(pk_set?),
            _ => Err(Error::UnexpectedReplicaKeysResponse(pk)),
        }
    }

    /// Send message and await validation and constructing of TransferAgreementProof
    async fn await_validation(
        &self,
        message: &ClientMessage,
        _id: DebitId,
    ) -> Result<TransferAgreementProof, Error> {
        info!("Awaiting transfer validation");

        let (sender, mut receiver) = channel::<Result<TransferValidated, Error>>(7);

        self.connection_manager
            .lock()
            .await
            .send_transfer_validation(&message, sender)
            .await?;

        let mut returned_errors = vec![];
        let mut response_count = 0;
        loop {
            match receiver.recv().await {
                Some(event) => match event {
                    Ok(transfer_validated) => {
                        response_count += 1;
                        let mut actor = self.transfer_actor.lock().await;
                        match actor.receive(transfer_validated) {
                            Ok(result) => {
                                if let Some(validation) = result {
                                    actor.apply(ActorEvent::TransferValidationReceived(
                                        validation.clone(),
                                    ))?;
                                    info!("Transfer successfully validated.");
                                    if let Some(dap) = validation.proof {
                                        self.connection_manager
                                            .lock()
                                            .await
                                            .remove_pending_transfer_sender(&message.id())
                                            .await?;
                                        return Ok(dap);
                                    }
                                } else {
                                    info!("Aggregated given SignatureShare.");
                                }
                            }
                            Err(e) => error!("Error accumulating SignatureShare: {:?}", e),
                        }
                    }
                    Err(e) => {
                        response_count += 1;
                        error!("Error receiving SignatureShare: {:?}", e);
                        returned_errors.push(e);

                        if returned_errors.len() > STANDARD_ELDERS_COUNT / 2 {
                            // TODO: Check + handle that errors are the same
                            let error = returned_errors.remove(0);

                            if let Err(e) = self
                                .connection_manager
                                .lock()
                                .await
                                .remove_pending_transfer_sender(&message.id())
                                .await
                            {
                                return Err(e);
                            } else {
                                return Err(error);
                            }
                        }

                        continue;
                    }
                },
                None => continue,
            }

            // at any point if we've had enough responses in, let's clean up
            if response_count >= STANDARD_ELDERS_COUNT {
                // remove pending listener
                self.connection_manager
                    .lock()
                    .await
                    .remove_pending_transfer_sender(&message.id())
                    .await?;
            }
        }
    }
}

// --------------------------------
// Tests
// ---------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{create_test_client, create_test_client_with};
    use anyhow::{anyhow, Result};
    use rand::rngs::OsRng;
    use sn_data_types::Token;
    use std::str::FromStr;
    use tokio::time::{delay_for, Duration};

    #[tokio::test]
    pub async fn transfer_actor_creation_hydration_for_nonexistant_balance() -> Result<()> {
        let keypair = Keypair::new_ed25519(&mut OsRng);

        match create_test_client_with(Some(keypair), None).await {
            Ok(actor) => {
                assert_eq!(actor.get_local_balance().await, Token::from_str("0")? );
                Ok(())
            },
            Err(e) => Err(anyhow!("Should not error for nonexistent keys, only create a new instance with no history, we got: {:?}" , e))
        }
    }

    #[tokio::test]
    pub async fn transfer_actor_client_random_creation_gets_initial_balance() -> Result<()> {
        let actor = create_test_client().await
            .map_err(|err| anyhow!("Should not error for random client, only create a new instance with 10 token, we got: {:?}" , err))?;

        let mut bal = actor.get_balance().await;
        while bal.is_err() {
            delay_for(Duration::from_millis(200)).await;

            bal = actor.get_balance().await;
        }

        let mut tokens = bal?;
        while tokens != Token::from_str("10")? {
            delay_for(Duration::from_millis(200)).await;

            tokens = actor.get_balance().await?;
        }

        Ok(())
    }

    #[tokio::test]
    pub async fn transfer_actor_creation_hydration_for_existing_balance() -> Result<()> {
        // small delay for starting this test, which seems to have a problem when nodes are under stress..
        // delay_for(Duration::from_millis(200)).await;

        let keypair = Keypair::new_ed25519(&mut OsRng);

        {
            let mut initial_actor = create_test_client_with(Some(keypair.clone()), None).await?;
            let _ = initial_actor
                .trigger_simulated_farming_payout(Token::from_str("100")?)
                .await?;
        }

        let client_res = create_test_client_with(Some(keypair.clone()), None).await;

        // while client_res.is_err() {
        //     delay_for(Duration::from_millis(200)).await;

        //     client_res = create_test_client_with(Some(keypair.clone()), None).await;
        // }

        let client = client_res?;

        // Assert sender is debited.
        let mut _new_balance = client.get_balance().await?;
        let _desired_balance = Token::from_str("100")?;

        // loop until correct
        // while new_balance != desired_balance {
        //     delay_for(Duration::from_millis(200)).await;
        //     new_balance = client.get_balance().await?;
        // }

        assert_eq!(client.get_local_balance().await, Token::from_str("100")?);

        Ok(())
    }
}
