use core::array::SpanTrait;
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

#[test]
#[available_gas(20000000000)]
fn test_addr_to_hex() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();

    let addr: ContractAddress = contract_address_const::<0x123456>();
    let mut output = EthStarkResolver::InternalImpl::addr_to_bytes(@unsafe_state, addr);
    assert(output == array![0x12, 0x34, 0x56], 'unexpected translation');
}

#[test]
#[available_gas(20000000000)]
fn test_concat_hashes() {
    let mut unsafe_state = EthStarkResolver::unsafe_new_contract_state();

    let addr: ContractAddress = contract_address_const::<12345>();
    let output = EthStarkResolver::InternalImpl::concat_hashes(@unsafe_state, (1, 0x1234, 3, 4));
    assert(output.len() == 32 * 4, 'invalid size');
    assert(*output[31] == 1, 'expected 1');
    assert(*output[32 + 31] == 0x34, 'expected 0x34');
    assert(*output[32 + 30] == 0x12, 'expected 0x12');

    let mut i = 0;
    loop {
        if i == 31 {
            break;
        }
        assert(*output[i] == 0, 'expected 0');
        i += 1;
    };
}

// #[test]
// #[available_gas(20000000000)]
// fn test_example_print_bytes() {
//     let mut a = array![0x12, 0x34, 0x56];
//     let mut i = 64;
//     loop {
//         if i == 0 {
//             break;
//         }
//         i -= 1;
//         a.append(0);
//     };
//     print_31_bytes(a.span(), 1);
// }

fn print_31_bytes(bytes_arr: Span<u8>, start_index: usize) {
    let mut sum = 0;
    let temp = bytes_arr.len() - start_index;
    rec_sum_31_bytes(ref sum, bytes_arr.slice(start_index, if 31 > temp {
        temp
    } else {
        31
    }));
    sum.print();
}

fn rec_sum_31_bytes(ref sum: felt252, mut iter: Span<u8>) -> felt252 {
    match iter.pop_front() {
        Option::Some(x) => {
            let acc = rec_sum_31_bytes(ref sum, iter);
            sum += acc * (*x).into();
            return acc * 256;
        },
        Option::None => { return 1; },
    }
}
