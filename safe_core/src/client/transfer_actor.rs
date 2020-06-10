use safe_nd::{
    AData, ADataAddress, ADataAppendOperation, ADataEntries, ADataEntry, ADataIndex, ADataIndices,
    ADataOwner, ADataPermissions, ADataPubPermissionSet, ADataPubPermissions, ADataRequest,
    ADataUnpubPermissionSet, ADataUnpubPermissions, ADataUser, AppPermissions, ClientFullId,
    ClientRequest, DebitAgreementProof, IData, IDataAddress, IDataRequest, LoginPacket,
    LoginPacketRequest, MData, MDataAddress, MDataEntries, MDataEntryActions, MDataPermissionSet,
    MDataRequest, MDataSeqEntries, MDataSeqEntryActions, MDataSeqValue, MDataUnseqEntryActions,
    MDataValue, MDataValues, Message, MessageId, Money, MoneyRequest, PublicId, PublicKey, Request,
    ReplicaEvent, Error as SndError, TransferPropagated, SignatureShare, SignedTransfer, 
    RequestType, Response, SeqMutableData, Transfer, TransferRegistered, UnseqMutableData, XorName,
};
use safe_transfers::{ReplicaValidator, TransferActor as SafeTransferActor, TransfersSynched, ActorEvent};

use crate::client::ConnectionManager;
use crate::client::{sign_request, Client, SafeKey};
use crate::errors::CoreError;
use crdts::Dot;
use futures::channel::mpsc;
use futures::stream::StreamExt;
use rand::thread_rng;
use std::collections::HashMap;
use std::iter::Iterator;
use std::str::FromStr;
use log::{trace, warn, info, debug};
use threshold_crypto::{SecretKey, SecretKeySet, PublicKeySet};
use futures::lock::Mutex;
use std::sync::Arc;


async fn get_history( safe_key: SafeKey, mut cm: ConnectionManager ) -> Result<Vec<ReplicaEvent>, CoreError> {

    trace!("Get history for {:?}", safe_key );

    let message_id = MessageId::new();

    let request = Request::Money(MoneyRequest::GetHistory { 
        at: safe_key.public_key(),
                since_version: 0
    });

    // TODO: remove this unwrap
    let signature = Some(safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
        &request, message_id
    )))));

    let message = Message::Request {
        request,
        message_id: message_id.clone(),
        signature,
    };


    let _bootstrapped = cm.bootstrap(safe_key.clone()).await;

    // This is a normal response manager request. We want quorum on this for now...
    let res = cm.send(&safe_key.public_id(), &message).await?;

    match res {
        Response::GetHistory(history) => history.map_err(CoreError::from ),
        _ => Err(CoreError::from(format!("Bad response when retrieving account history {:?}",  res ) ))
    }
}


fn build_transfer(from: Dot<PublicKey>, to: PublicKey, amount: Money) -> Transfer {
    Transfer {
        id: from,
        to,
        amount,
    }
}

/// Handle Money Transfers, requests and locally stores a balance
#[derive(Clone, Debug)]
pub struct TransferActor {
    transfer_actor: Arc<Mutex<SafeTransferActor<ClientTransferValidator>>>,
    safe_key: SafeKey,
    replicas_pk_set: PublicKeySet,
    simulated_farming_payout_dot: Dot<PublicKey>,
    // replicas_sk_set: SecretKeySet,

    // Todo, do we need this Arc for clonability? When are we cloinging
    pending_validations: HashMap<MessageId, mpsc::UnboundedSender<DebitAgreementProof>>,
}

/// Simple client side validations
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientTransferValidator {}

impl ReplicaValidator for ClientTransferValidator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}


fn get_random_sk_set() -> SecretKeySet {
    // fake bls keyset for our "replica", which currently doesn't exist locally or do anything if it did.
    // let bls_secret_key = 
    SecretKeySet::random(1, &mut thread_rng() )
    // bls_secret_key.public_keys()

}

/// Handle all transfers and messaging around transfers for a given client.
impl TransferActor {

    /// Create a new Transfer Actor for a previously unused public key
    pub async fn new(
        safe_key: SafeKey,
        cm: ConnectionManager,
    ) -> Result<Self, CoreError> {
    
        let simulated_farming_payout_dot = Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);
       let replicas_sk_set = get_random_sk_set();
       let replicas_pk_set = replicas_sk_set.public_keys();

        let validator = ClientTransferValidator {};
        // TODO: Handle this error when None... would this ever be None?
        let transfer_actor = Arc::new(Mutex::new(SafeTransferActor::new(safe_key.clone(),  replicas_pk_set.clone(), validator)));

        let pending_validations: HashMap<MessageId, mpsc::UnboundedSender<DebitAgreementProof>> =
            HashMap::new();



        let mut actor = Self {
            safe_key: safe_key.clone(),
            transfer_actor,
            pending_validations,
            replicas_pk_set,
            simulated_farming_payout_dot
            // replicas_sk_set
        };

        #[cfg(feature="testing")]
        {
            // we're testing, and currently a lot of tests expect 10 money to start
            // let _ = actor.trigger_simulated_farming_payout(cm, safe_key.public_key(), Money::from_str("0")? ).await?;
            let _ = actor.trigger_simulated_farming_payout(cm, safe_key.public_key(), Money::from_str("10")? ).await?;
            // let _ = actor.trigger_simulated_farming_payout(cm, safe_key.public_key(), Money::from_str("10.000000001")? ).await?;

            // info!("New test actor created and received a farming payout of: {:?}", actor.get_local_balance().await);
        }

        Ok(actor)
    }

    
      /// Create a Transfer Actor from an existing public key with an account history
      pub async fn for_existing_account(
        safe_key: SafeKey,
        // history: History,
        cm: ConnectionManager,
    ) -> Result<Self, CoreError> {
        // we need transfer history and to pass this into account.
        println!("SETUP FOR EXISTING ACCOUNT");
        let simulated_farming_payout_dot = Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);

        let history = get_history( safe_key.clone(), cm ).await?;
        let replicas_sk_set = get_random_sk_set();
        let replicas_pk_set = replicas_sk_set.public_keys();
        let validator = ClientTransferValidator {};

        // println!("SETUP FOR EXISTING ACCOUNT >>>>>>>>>>.. has history");


        // let _sender = Dot::new(PublicKey::from(SecretKey::random().public_key()), 0);

        // TODO: Handle this error when None... would this ever be None?
        let mut transfer_actor = SafeTransferActor::new( safe_key.clone(), replicas_pk_set.clone(), validator);

        // TODO: as mock, we want the balance and that in the actor at this point.
        // is it simpler to just run a replica as the bank?
        let synced_transfers = transfer_actor.synch(history)?;

        transfer_actor.apply( ActorEvent::TransfersSynched(synced_transfers));
        // println!("SETUP FOR EXISTING ACCOUNT >>>>>>>>>>.. post sync {:?}", rrrr);

        // .ok_or(CoreError::from("Safe Transfers Actor could not be instantiated".to_string()))?;
        let pending_validations: HashMap<MessageId, mpsc::UnboundedSender<DebitAgreementProof>> =
            HashMap::new();
        Ok(Self {
            safe_key,
            transfer_actor: Arc::new(Mutex::new( transfer_actor) ),
            pending_validations,
            replicas_pk_set,
            simulated_farming_payout_dot
            // replicas_sk_set
        })
    }

    // TODO get_local_balance
    // is SafeKey needed here for an actor?
    // Send as vs use this need to be sorted ooooot
    /// Get the account balance without querying the network
    pub async fn get_local_balance(&self) -> Money {
        self.transfer_actor.lock().await.balance()
    }

    /// Handle a validation request response.
    pub async fn handle_validation_response(&mut self, response: Response, message_id: &MessageId) -> Result<(), CoreError> {
        let validation = match response {
            Response::TransferValidation(res) => res?,
            _ => {
                return Err(CoreError::from(format!(
                    "Unexpected response received at TransferActor, {:?}",
                    response
                )))
            }
        };

        // TODO: where should we handle this error? On receive. Or via send?
        let transfer_validation = self.transfer_actor.lock().await.receive(validation)?;

        // if we have a proof, lets send it back to our waiting send func...
        if let Some(proof) = transfer_validation.proof {
            let mut sender = self
                .pending_validations
                .remove(message_id)
                .ok_or(CoreError::from(
                    "No pending validation found for debit proof.",
                ))?;
            sender.unbounded_send(proof);
            sender.disconnect()
        };

        Ok(())
    }

    /// Get the current coin balance.
    pub async fn get_balance_from_network(
        &self,
        // client_id: &ClientFullId,
        cm: &mut ConnectionManager,
    ) -> Result<Money, CoreError>
    where
        Self: Sized,
    {
        // first get history and rehydrate

        trace!("Get balance for {:?}", self.safe_key);

        let identity = self.safe_key.clone();
        // let identity = SafeKey::client(client_id.clone());
        let pub_id = identity.public_id();

        let message_id = MessageId::new();

        let request =   Request::Money(MoneyRequest::GetBalance(pub_id.public_key()));
        // TODO: remove this unwrap
        let signature = Some(self.safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
            &request, message_id
        )))));

        let message = Message::Request {
            request,
            message_id: message_id.clone(),
            signature,
        };


        let _bootstrapped = cm.bootstrap(identity).await;

        // This is a normal response manager request. We want quorum on this for now...
        match cm.send(&pub_id, &message).await? {
            Response::GetBalance(balance) => balance.map_err(CoreError::from),
            _ => Err(CoreError::from("Unexpected response when querying balance"))
        }

        // TODO return actual things..
        // Ok(Money::from_str("10000000000000000")?)
    }

    // TODO: remove need for passing cm
    /// Send money
    pub async fn send_money(
        &mut self,
        mut cm: ConnectionManager,
        to: PublicKey,
        amount: Money,
    ) -> Result<Response, CoreError> {
        //set up message
        let safe_key = self.safe_key.clone();
        println!("'''''''''''''''''''''''''''''''''''''''''''''''''''''''Sending money from {:?}, to {:?}", safe_key.public_key(), to);
        println!("our local balance at this point: {:?}... and we're sending {:?}", self.get_local_balance().await, amount);
        
        // first make sure our balance is up to date
        let history = get_history( self.safe_key.clone(), cm.clone() ).await?;
        
        if history.len() > 0
        {
            let synced_transfers = self.transfer_actor.lock().await.synch(history)?;
            self.transfer_actor.lock().await.apply( ActorEvent::TransfersSynched(synced_transfers));
        }

        let signed_transfer = self.transfer_actor.lock().await.transfer(amount, to)?.signed_transfer;


        println!("signed transfer recievedddd;");
        let request = Request::Money(MoneyRequest::ValidateTransfer { signed_transfer });
        let message_id = MessageId::new();

        // TODO: remove this unwrap
        let signature = Some(safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
            &request, message_id
        )))));


        let message = Message::Request {
            request,
            message_id: message_id.clone(),
            signature,
        };

        let pub_id = safe_key.public_id();

        let _bootstrapped = cm.bootstrap(safe_key.clone()).await;

        println!("!!!!!!!!!!!!!!!!!!!!SENDING MONEY form acocunt with balance: {:?}", self.get_local_balance().await );
       

            // TODO: make it clearer
            #[cfg(feature="mock-network")]
            {
                // no waiting on validation needed for mock
                return cm.send(&pub_id, &message).await
                //  {
                //     Response::TransferRegistration(res) => match res {
                //         Ok(deets) => {
                //             // sender.unbounded_send( deets.debit_proof );
                //             Ok(deets.debit_proof)
                //         },
                //         Err(e) => Err(CoreError::from(e))
                        
                //     },
                //     _ => Err(CoreError::from("Unexpected response in mock-network await validation"))
                // }

                // return Ok(Response::TransferRegistration(Ok(
                //     TransferRegistered {
                //         debit_proof: proof
                //     }
                // )))
            }

            let proof: DebitAgreementProof = self
            .await_validation(message_id, &pub_id, &message, cm.clone())
            .await?;
            // register the transaction on the network
            let registration_message_id = MessageId::new();
            
            let register_transaction_request = Request::Money(MoneyRequest::RegisterTransfer { proof });
            
            let register_signature = Some(safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
                &register_transaction_request,
                registration_message_id
            )))));
            let message = Message::Request {
                request: register_transaction_request,
                message_id: registration_message_id.clone(),
                signature: register_signature,
            };
            
        // TODO what will be the correct reponse here?... We have it validated, so registered?
        cm.send(&pub_id, &message).await
    }

    #[cfg(feature="testing")]
    /// Simulate a farming payout
    pub async fn trigger_simulated_farming_payout(
        &mut self,
        mut cm: ConnectionManager,
        to: PublicKey,
        amount: Money,
    ) -> Result<Response, CoreError> {
        info!("Triggering a test farming payout to: {:?}", &to);
        // let mut rng = thread_rng();
        // let random_safe_key = SafeKey::client(ClientFullId::new_ed25519(rand::random() ));


        let safe_key = self.safe_key.clone();
        self.simulated_farming_payout_dot.apply_inc();

        let simulated_transfer = Transfer {
            to, 
            amount,
            id: self.simulated_farming_payout_dot
        };

        let request = Request::Money(MoneyRequest::SimulatePayout { transfer:  simulated_transfer.clone() });
        let message_id = MessageId::new();

          // TODO: remove this unwrap
          let signature = Some(safe_key.sign(&unwrap::unwrap!(bincode::serialize(&(
            &request, message_id
        )))));

        let message = Message::Request {
            request,
            message_id: message_id.clone(),
            signature,
        };

        let pub_id = safe_key.public_id();

        let _bootstrapped = cm.bootstrap(safe_key.clone()).await;
        let res = cm.send(&pub_id, &message).await?;

            // println!("simulated farming,,,,,,,,,,,,,,,,,,,,,,,res from cm:  {:?}", res);

        // nonsense signature that we don't care about
        let fake_signature = safe_key.sign(b"mock-key");
        
        // If we're getting the payout for our own actor, update it here
        if to == self.safe_key.public_key() 
        {
            // println!("In actor updatesssssss to add {:?}", amount);
            // update our actor with this new info
            let event = match res.clone() {
                Response::TransferRegistration(res) => {
                    let transfer_registered = res?;
                    
                    
                    // we need our fake transfer to be signed by debiting replicas sig.
                    let fake_signed_transfer = SignedTransfer {
                        transfer: simulated_transfer.clone(), 
                        actor_signature: fake_signature.clone()
                    };
                    let serialized_signed_transfer = bincode::serialize(&fake_signed_transfer)?;
                    let propogated = TransferPropagated {
                        debit_proof: DebitAgreementProof {
                            signed_transfer: fake_signed_transfer,
                            debiting_replicas_sig: safe_key.clone().sign( &serialized_signed_transfer ), // this sig needs to match debiting replicas PK
                        },
                        debiting_replicas: safe_key.clone().public_key(), 
                        crediting_replica_sig: SignatureShare { index: 0, share: get_random_sk_set().secret_key_share(0).sign(b"boop") }
                    };
                    
                    ReplicaEvent::TransferPropagated( propogated )
                    
                },
                _ => { return Err( CoreError::from("Error registering simulated farming event"))}
            };

            // Create transfers synced to apply to our actor
            // println!("aaaaa!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! {:?}", event);
            let transfers_synced: TransfersSynched  = self.transfer_actor.lock().await.synch(vec![event])?;
            self.transfer_actor.lock().await.apply( ActorEvent::TransfersSynched(transfers_synced));
            // println!("bbbbbbbbbbbbbbbbbbbb!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!, now our balance should be, {:?}", amount);
        
        }
        // println!("SENDING BACK>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> {:?}", res);
        Ok(res)

    }

    /// Send message and await validation and constructin of DebitAgreementProof
    async fn await_validation(
        &mut self,
        message_id: MessageId,
        pub_id: &PublicId,
        message: &Message,
        mut cm: ConnectionManager,
    ) -> Result<DebitAgreementProof, CoreError> {

        println!("Awaiting transfer validation");

        
        #[cfg(feature="mock-network")]
        {
            // let res = cm.send(&pub_id, &message).await?;

            // println!("mock network response received.... {:?}", res);

            // sender.send(res);

            match cm.send(&pub_id, &message).await? {
                Response::TransferRegistration(res) => match res {
                    Ok(deets) => {
                        // sender.unbounded_send( deets.debit_proof );
                        Ok(deets.debit_proof)
                    },
                    Err(e) => Err(CoreError::from(e))
                    
                },
                _ => Err(CoreError::from("Unexpected response in mock-network await validation"))
            }
        }

        #[cfg(not(feature="mock-network"))]
        {       
            let (sender, mut receiver) = mpsc::unbounded::<DebitAgreementProof>();

            self.pending_validations.insert(message_id, sender);

            cm.send_for_validation(&pub_id, &message, self).await?;
            match receiver.next().await {
                Some(res) => Ok(res),
                None => Err(CoreError::from(
                    "No debit proof returned from client transfer actor.",
                )),
            }
        }

    }
}

// TODO: start setting up some tests for this.
// update response_manager test for this case....
// THEN: Try out an integration test w/ core
// ensure actor is created there.



// TODO: Do we need "new" to actually instantiate with a transfer?...
#[cfg(all(test, feature="testing"))]
mod tests {

    use crate::client::attempt_bootstrap;
    use crate::config_handler::Config;

    use super::*;

    async fn get_keys_and_connection_manager() -> (SafeKey, ConnectionManager) {
        let mut rng = thread_rng();
        let client_safe_key = SafeKey::client(ClientFullId::new_ed25519(&mut rng));

        // println!("Generating a safe key {:?}", &client_safe_key);
        let (net_sender, _net_receiver) = mpsc::unbounded();

        // Create the connection manager
        let connection_manager = attempt_bootstrap(
            &Config::new().quic_p2p,
            &net_sender,
            client_safe_key.clone(),
        )
        .await
        .unwrap();

        (client_safe_key, connection_manager)
    }
    #[tokio::test]
    async fn transfer_actor_creation() {
        let ( safe_key, cm) = get_keys_and_connection_manager().await;

    
        let _transfer_actor =
            TransferActor::new(safe_key, cm.clone())
                .await
                .unwrap();
    }

    #[tokio::test]
    async fn transfer_actor_creation_hydration_for_nonexistant_balance() {
        let ( safe_key, cm) = get_keys_and_connection_manager().await;

        match
            TransferActor::for_existing_account(safe_key, cm.clone())
                .await {
                    Ok(_) => panic!("Account should not exist"),
                    Err(e) => {
                        assert_eq!( e.to_string(), "Data error -> Balance does not exist".to_string() )
                    }
                }
    }



    // TODO: only do this for real vault until we a local replica bank
    #[tokio::test]
    #[cfg(not(feature="mock-network"))]
    async fn transfer_actor_creation_hydration_for_existing_balance() {
        let ( safe_key, cm) = get_keys_and_connection_manager().await;
        let ( safe_key_two, cm) = get_keys_and_connection_manager().await;

        let mut initial_actor = TransferActor::new(safe_key.clone(), cm.clone())
            .await
                .unwrap();

        let _ = initial_actor.trigger_simulated_farming_payout( cm.clone(), safe_key_two.public_key(), Money::from_str("100").unwrap() ).await.unwrap();
        
        
        match
            TransferActor::for_existing_account(safe_key_two, cm.clone())
                .await {
                    Ok(_) => assert!(true),
                    Err( e) =>  panic!("Account should exist {:?}", e),
                }
    }
}
