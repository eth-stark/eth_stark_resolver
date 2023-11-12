mod interface;
#[cfg(test)]
mod tests;

#[starknet::interface]
trait IFactsRegistry<TContractState> {
    fn get_slot_value(
        self: @TContractState, account: felt252, block: u256, slot: u256
    ) -> Option<u256>;
}


#[starknet::contract]
mod EthStarkResolver {
    use core::traits::Into;
    use core::array::ArrayTrait;
    use core::array::SpanTrait;
    use option::OptionTrait;
    use starknet::ContractAddress;
    use starknet::contract_address::ContractAddressZeroable;
    use starknet::{get_caller_address, get_contract_address, get_block_timestamp};
    use storage_read::{main::storage_read_component, interface::IStorageRead};
    use naming::interface::resolver::{IResolver, IResolverDispatcher, IResolverDispatcherTrait};
    use eth_stark_resolver::interface::IEnsMigrator;
    use starknet::{
        EthAddress,
        secp256_trait::{
            Secp256Trait, Secp256PointTrait, recover_public_key, is_signature_entry_valid, Signature
        },
        secp256k1::{Secp256k1Point, Secp256k1PointImpl}, SyscallResult, SyscallResultTrait
    };
    use keccak::keccak_u256s_be_inputs;
    use starknet::eth_signature::verify_eth_signature;
    use super::{IFactsRegistryDispatcherTrait, IFactsRegistryDispatcher};

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        StorageReadEvent: storage_read_component::Event
    }

    #[derive(Drop, starknet::Event)]
    struct DomainMint {
        #[key]
        domain: felt252,
        owner: u128,
        expiry: u64
    }

    #[storage]
    struct Storage {
        #[substorage(v0)]
        storage_read: storage_read_component::Storage,
    }

    const HERODOTUS_FACTS_REGISTRY: felt252 =
        0x07c88f02f0757b25547af4d946445f92dbe3416116d46d7b2bd88bcfad65a06f;
    const ENS_MIDDLEWARE_ADDRESS: felt252 = 0xB6920Bc97984b454A2A76fE1Be5e099f461Ed9c8;

    component!(path: storage_read_component, storage: storage_read, event: StorageReadEvent);

    #[abi(embed_v0)]
    impl StorageReadComponent = storage_read_component::StorageRead<ContractState>;

    #[external(v0)]
    impl ResolverImpl of IResolver<ContractState> {
        fn resolve(
            self: @ContractState, domain: Span<felt252>, field: felt252, hint: Span<felt252>
        ) -> felt252 {
            // todo: read the resolving set by the controler
            1
        }
    }

    #[external(v0)]
    impl IEnsMigratorImpl of IEnsMigrator<ContractState> {
        fn claim(
            ref self: ContractState,
            unicode_domain: Span<(felt252, felt252)>,
            msg_hash: u256,
            signature: Signature,
            block_number: u256,
            slot: u256,
            owner_address: EthAddress,
        ) { // todo:
            // verify that signature corresponds to the hash

            // step1. To make sure owner_address is the owner of person who calling the function by verifying signature
            verify_eth_signature(msg_hash, signature, owner_address);

            // step2. Retrieve ENS owner address from Herodotous fact registry
            let fact_registry_dispatcher = IFactsRegistryDispatcher {
                contract_address: HERODOTUS_FACTS_REGISTRY.try_into().unwrap()
            };
            let ens_owner: EthAddress = fact_registry_dispatcher
                .get_slot_value(ENS_MIDDLEWARE_ADDRESS, block_number, slot)
                .unwrap()
                .into();

            // step3. Compare ens owner from Herodotous with signature owner
            // assert msg_hash is hash('redeem .eth domain', eth_domain, caller_address)
            if ens_owner == owner_address {
                let domain = unicode_domain.at(0);
            // write caller_address as controller of domain
            // emits an event saying that caller_address claimed domain
            }
        }


        fn set_resolving(
            ref self: ContractState, domain: Span<felt252>, field: felt252, data: felt252
        ) { // ensure caller is controller
        // sets mapping read by resolve
        }
    }


    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn get_message_hash(
            self: @ContractState,
            unicode_domain: Span<(u128, u128, u128)>,
            receiver: ContractAddress
        ) -> felt252 {
            1
        }

        fn concat_eth_domain(
            self: @ContractState, mut unicode_domain: Span<(u128, u128, u128)>
        ) -> Array<felt252> {
            let mut bytes_stream = Default::default();
            loop {
                match unicode_domain.pop_front() {
                    Option::Some(x) => {
                        let (first, second, third) = *x;
                        self.rec_add_chars(ref bytes_stream, 16, first);
                        self.rec_add_chars(ref bytes_stream, 16, second);
                        self.rec_add_chars(ref bytes_stream, 16, third);
                        bytes_stream.append('.');
                    },
                    Option::None => { break; }
                }
            };
            bytes_stream.append('e');
            bytes_stream.append('t');
            bytes_stream.append('h');
            bytes_stream
        }

        fn rec_add_chars(
            self: @ContractState, ref arr: Array<felt252>, str_len: felt252, str: u128
        ) {
            if str_len == 0 {
                return;
            }
            let (str, char) = DivRem::div_rem(str, 256_u128.try_into().unwrap());
            self.rec_add_chars(ref arr, str_len - 1, str);
            if char != 0 {
                arr.append(char.into());
            }
        }

        fn addr_to_dec_chars(self: @ContractState, addr: ContractAddress) -> Array<u8> {
            let felted: felt252 = addr.into();
            let ten: NonZero<u256> = 10_u256.try_into().unwrap();
            let to_add = self.div_rec(felted.into(), ten);
            to_add
        }

        fn div_rec(self: @ContractState, value: u256, divider: NonZero<u256>) -> Array<u8> {
            let (value, digit) = DivRem::div_rem(value, divider);
            let mut output = if value == 0 {
                Default::default()
            } else {
                self.div_rec(value, divider)
            };
            output.append(48 + digit.try_into().unwrap());
            output
        }
    }
}

