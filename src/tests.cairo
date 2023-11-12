use array::ArrayTrait;
use starknet::{
    contract_address::contract_address_const, class_hash::Felt252TryIntoClassHash, ContractAddress,
    SyscallResultTrait
};
use eth_stark_resolver::{EthStarkResolver, EthStarkResolver::InternalImpl, interface::IEnsMigrator};
use traits::TryInto;
use debug::PrintTrait;


#[test]
#[available_gas(20000000000)]
fn test_concat_eth_domain() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();

    let domain = array![('alp', 'h', 'a'), ('bravo', 0, 0)];
    let output = EthStarkResolver::InternalImpl::concat_eth_domain(@unsafe_state, domain.span());

    assert(
        output == array!['a', 'l', 'p', 'h', 'a', '.', 'b', 'r', 'a', 'v', 'o', '.', 'e', 't', 'h'],
        'unexpected result'
    );
}

#[test]
#[available_gas(20000000000)]
fn test_addr_to_dec_chars() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();

    let addr: ContractAddress = contract_address_const::<12345>();
    let output = EthStarkResolver::InternalImpl::addr_to_dec_chars(@unsafe_state, addr);

    assert(output == array!['1', '2', '3', '4', '5'], 'unexpected result');
}
