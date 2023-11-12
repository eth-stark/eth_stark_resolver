use starknet::{ContractAddress, ClassHash};
use starknet::secp256k1::Signature;
use starknet::EthAddress;

#[starknet::interface]
trait IEnsMigrator<TContractState> {
    fn claim(
        ref self: TContractState,
        unicode_domain: Span<(felt252, felt252)>,
        msg_hash: u256,
        signature: Signature,
        block_number: u256,
        slot: u256,
        owner_address: EthAddress,
    );

    fn set_resolving(
        ref self: TContractState, domain: Span<felt252>, field: felt252, data: felt252
    );
}
