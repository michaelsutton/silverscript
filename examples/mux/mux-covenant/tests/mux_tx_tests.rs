use std::fs;

use blake2b_simd::Params as Blake2bParams;
use kaspa_consensus_core::tx::{
    Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::{pay_to_script_hash_script, pay_to_script_hash_signature_script};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use mux_covenant::{mux_contract_path, worker_a_contract_path, worker_b_contract_path};

fn load_contract_source(path: &'static str) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn template_parts_and_hash(source: &str, state: &[Expr<'_>]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let compiled = compile_contract(source, state, CompileOptions::default()).expect("compile template source succeeds");
    let layout = compiled.state_layout;
    let prefix = compiled.script[..layout.start].to_vec();
    let suffix = compiled.script[layout.start + layout.len..].to_vec();
    let hash = Blake2bParams::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize().as_bytes().to_vec();
    (prefix, suffix, hash)
}

fn test_input(index: u32, signature_script: Vec<u8>) -> TransactionInput {
    TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        sequence: 0,
        sig_op_count: 0,
    }
}

fn execute_input(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new();
    let sig_cache = kaspa_txscript::caches::Cache::new(10_000);
    let input = tx.inputs[input_idx].clone();
    let populated = kaspa_consensus_core::tx::PopulatedTransaction::new(&tx, entries);
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    let mut vm = kaspa_txscript::TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        kaspa_txscript::EngineCtx::new(&sig_cache).with_reused(&reused_values),
        kaspa_txscript::EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn run_p2sh_transition(input_contract: &CompiledContract, function: &str, args: Vec<Expr<'_>>, output_contract: &CompiledContract) {
    let sigscript = input_contract.build_sig_script(function, args).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_contract.script.clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let input_spk = pay_to_script_hash_script(&input_contract.script);
    let output_spk = pay_to_script_hash_script(&output_contract.script);
    let output = TransactionOutput { value: 1000, script_public_key: output_spk, covenant: None };
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, input_spk, 0, tx.is_coinbase(), None);
    let result = execute_input(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "{function} runtime failed: {}", result.unwrap_err());
}

#[test]
fn mux_routes_and_workers_return_to_mux() {
    let mux_source = load_contract_source(mux_contract_path());
    let a_source = load_contract_source(worker_a_contract_path());
    let b_source = load_contract_source(worker_b_contract_path());

    let (mux_prefix, mux_suffix, mux_hash) =
        template_parts_and_hash(&mux_source, &[vec![0x11u8; 32].into(), vec![0x21u8; 32].into(), vec![0x31u8; 32].into(), 5.into()]);
    let (a_prefix, a_suffix, a_hash) =
        template_parts_and_hash(&a_source, &[vec![0x41u8; 32].into(), vec![0x51u8; 32].into(), vec![0x61u8; 32].into(), 5.into()]);
    let (b_prefix, b_suffix, b_hash) =
        template_parts_and_hash(&b_source, &[vec![0x71u8; 32].into(), vec![0x81u8; 32].into(), vec![0x91u8; 32].into(), 5.into()]);

    let state = [mux_hash.clone().into(), a_hash.clone().into(), b_hash.clone().into(), 5.into()];

    let mux = compile_contract(&mux_source, &state, CompileOptions::default()).expect("compile mux succeeds");
    let a = compile_contract(&a_source, &state, CompileOptions::default()).expect("compile A succeeds");
    let b = compile_contract(&b_source, &state, CompileOptions::default()).expect("compile B succeeds");
    let mux_after_a = compile_contract(
        &mux_source,
        &[mux_hash.clone().into(), a_hash.clone().into(), b_hash.clone().into(), 6.into()],
        CompileOptions::default(),
    )
    .expect("compile mux after A succeeds");
    let mux_after_b = compile_contract(
        &mux_source,
        &[mux_hash.clone().into(), a_hash.clone().into(), b_hash.clone().into(), 7.into()],
        CompileOptions::default(),
    )
    .expect("compile mux after B succeeds");

    run_p2sh_transition(&mux, "route", vec![0.into(), a_prefix.clone().into(), a_suffix.clone().into()], &a);
    run_p2sh_transition(&mux, "route", vec![1.into(), b_prefix.clone().into(), b_suffix.clone().into()], &b);
    run_p2sh_transition(&a, "apply", vec![mux_prefix.clone().into(), mux_suffix.clone().into()], &mux_after_a);
    run_p2sh_transition(&b, "apply", vec![mux_prefix.into(), mux_suffix.into()], &mux_after_b);
}
