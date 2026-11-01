#![cfg_attr(not(feature = "std"), no_std)]

use ink::prelude::{vec, Vec};
use frame_support::{
    decl_module, decl_storage, decl_event, decl_error, ensure, dispatch::DispatchResult,
};
use frame_system::ensure_signed;
use sp_runtime::traits::{CheckedAdd, CheckedSub, Zero};
use sp_std::collections::btree_map::BTreeMap;
use crate::{
    quantum_secure::QuantumSecure,
    zkp_verification::{BLEEPZKPModule, TransactionCircuit},
    state_merkle::calculate_merkle_root,
    interoperability::BLEEPInteroperabilityModule,
};

// --- FRAME Module for Core Tokenomics ---
pub trait Config: frame_system::Config {
    type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
}

decl_storage! {
    trait Store for Module<T: Config> as BleepToken {
        // Core Tokenomics
        TotalSupply get(fn total_supply): u128;
        Balances get(fn balances): map hasher(blake2_128_concat) T::AccountId => u128;
        Allowances get(fn allowances): map hasher(blake2_128_concat) (T::AccountId, T::AccountId) => u128;

        // Governance
        Owner get(fn owner): T::AccountId;
        BurnRate get(fn burn_rate): u128; // Burn rate in basis points
        MintingCap get(fn minting_cap): u128; // Annual minting cap
        FeeCollector get(fn fee_collector): T::AccountId;
        TransactionFee get(fn transaction_fee): u128; // Fee in basis points

        // Cross-Chain
        TrustedChainIds get(fn trusted_chain_ids): Vec<u32>;
        CrossChainBridgeAddress get(fn cross_chain_bridge_address): T::AccountId;
    }
}

decl_event! {
    pub enum Event<T> where AccountId = <T as frame_system::Config>::AccountId {
        Transfer(AccountId, AccountId, u128),
        Burn(AccountId, u128),
        CrossChainTransfer(AccountId, u128, u32),
        GovernanceUpdate(AccountId),
        MetadataUpdated(AccountId, Vec<u8>), // Metadata event
        ZKPValidated(AccountId, Vec<u8>),    // ZKP event
    }
}

decl_error! {
    pub enum Error for Module<T: Config> {
        InsufficientBalance,
        Unauthorized,
        InvalidOperation,
        InvalidChainID,
        MetadataError,
        ProofValidationError,
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        /// Transfer tokens between accounts with burn mechanism
        #[weight = 10_000]
        fn transfer(origin, to: T::AccountId, amount: u128) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            ensure!(amount > 0, Error::<T>::InvalidOperation);

            let sender_balance = Self::balances(&sender);
            ensure!(sender_balance >= amount, Error::<T>::InsufficientBalance);

            let burn_amount = amount * Self::burn_rate() / 10_000;
            let transfer_amount = amount - burn_amount;

            <Balances<T>>::insert(&sender, sender_balance - amount);
            <Balances<T>>::insert(&to, Self::balances(&to) + transfer_amount);
            <TotalSupply>::put(Self::total_supply() - burn_amount);

            Self::deposit_event(RawEvent::Transfer(sender.clone(), to, transfer_amount));
            Self::deposit_event(RawEvent::Burn(sender, burn_amount));
            Ok(())
        }

        /// Cross-chain token transfer with trusted chain ID validation
        #[weight = 10_000]
        fn cross_chain_transfer(origin, amount: u128, chain_id: u32) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            ensure!(Self::trusted_chain_ids().contains(&chain_id), Error::<T>::InvalidChainID);

            let sender_balance = Self::balances(&sender);
            ensure!(sender_balance >= amount, Error::<T>::InsufficientBalance);

            <Balances<T>>::insert(&sender, sender_balance - amount);
            <TotalSupply>::put(Self::total_supply() - amount);

            Self::deposit_event(RawEvent::CrossChainTransfer(sender, amount, chain_id));
            Ok(())
        }

        /// Update the burn rate (restricted to the owner)
        #[weight = 10_000]
        fn update_burn_rate(origin, new_rate: u128) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            ensure!(sender == Self::owner(), Error::<T>::Unauthorized);

            <BurnRate>::put(new_rate);
            Self::deposit_event(RawEvent::GovernanceUpdate(sender));
            Ok(())
        }

        /// Validate a ZKP for secure actions
        #[weight = 10_000]
        fn validate_zkp(origin, proof: Vec<u8>, public_inputs: Vec<u8>) -> DispatchResult {
            let sender = ensure_signed(origin)?;

            // ZKP validation logic
            let zkp_module = BLEEPZKPModule::unconfigured();
            let is_valid = zkp_module.verify_proof(&proof, &public_inputs)
                .map_err(|_| Error::<T>::ProofValidationError)?;

            ensure!(is_valid, Error::<T>::ProofValidationError);

            Self::deposit_event(RawEvent::ZKPValidated(sender, proof));
            Ok(())
        }
    }
}

// --- ink! Contract for Advanced Programmability ---
#[ink::contract]
mod bleep_pat {
    use super::*;

    #[ink(storage)]
    pub struct BleepPAT {
        metadata: ink::storage::Mapping<Vec<u8>, Vec<u8>>, // Metadata storage
        owner: AccountId,
        quantum_secure: QuantumSecure, // Integrated quantum security
    }

    impl BleepPAT {
        /// Initialize the contract with the owner
        #[ink(constructor)]
        pub fn new(owner: AccountId) -> Self {
            Self {
                metadata: ink::storage::Mapping::default(),
                owner,
                quantum_secure: QuantumSecure::new().unwrap(), // Initialize QuantumSecure
            }
        }

        /// Set metadata key-value pair with encryption
        #[ink(message)]
        pub fn set_metadata(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
            let caller = self.env().caller();
            ensure!(caller == self.owner, "Unauthorized");

            let encrypted_value = self
                .quantum_secure
                .encrypt(&value)
                .map_err(|_| "Encryption Failed".to_string())?;
            self.metadata.insert(&key, &encrypted_value);

            Self::emit_event_metadata_updated(&caller, key.clone());
            Ok(())
        }

        /// Get metadata by key with decryption
        #[ink(message)]
        pub fn get_metadata(&self, key: Vec<u8>) -> Option<Vec<u8>> {
            self.metadata.get(&key).and_then(|encrypted_value| {
                self.quantum_secure.decrypt(&encrypted_value).ok()
            })
        }

        /// Update the contract owner with validation
        #[ink(message)]
        pub fn update_owner(&mut self, new_owner: AccountId, proof: Vec<u8>) -> Result<(), String> {
            let caller = self.env().caller();
            ensure!(caller == self.owner, "Unauthorized");

            // Verify proof before updating owner
            let public_inputs = vec![caller.as_ref().to_vec(), new_owner.as_ref().to_vec()];
            let zkp_module = BLEEPZKPModule::unconfigured();
            let is_valid = zkp_module.verify_proof(&proof, &public_inputs)
                .map_err(|_| "Invalid Proof".to_string())?;

            ensure!(is_valid, "Proof Verification Failed");
            self.owner = new_owner;
            Ok(())
        }

        /// Emit a metadata update event
        fn emit_event_metadata_updated(caller: &AccountId, key: Vec<u8>) {
            Self::env().emit_event(MetadataUpdated {
                caller: caller.clone(),
                key,
            });
        }
    }

    /// Events emitted by the contract
    #[ink(event)]
    pub struct MetadataUpdated {
        #[ink(topic)]
        caller: AccountId,
        #[ink(topic)]
        key: Vec<u8>,
    }
  }