use std::fs;

use blake2b_simd::Params as Blake2bParams;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    CovenantBinding, GenesisCovenantGroup, PopulatedTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{pay_to_script_hash_script, pay_to_script_hash_signature_script, EngineCtx, EngineFlags, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;
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
        sig_op_count: 1,
    }
}

fn covenant_output(compiled: &CompiledContract<'_>, authorizing_input: u16, covenant_id: Hash) -> TransactionOutput {
    TransactionOutput {
        value: 1_000,
        script_public_key: pay_to_script_hash_script(&compiled.script),
        covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
    }
}

fn covenant_utxo(compiled: &CompiledContract<'_>, covenant_id: Hash) -> UtxoEntry {
    UtxoEntry::new(1_500, pay_to_script_hash_script(&compiled.script), 0, false, Some(covenant_id))
}

fn populate_single_output_genesis_covenant(compiled: &CompiledContract<'_>) -> Hash {
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x42u8; 32]), index: 0 },
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 0,
    };
    let output = TransactionOutput { value: 1_000, script_public_key: pay_to_script_hash_script(&compiled.script), covenant: None };
    let mut tx = Transaction::new(1, vec![input], vec![output], 0, Default::default(), 0, vec![]);
    tx.populate_genesis_covenants(&[GenesisCovenantGroup::new(0, vec![0])]).expect("populate genesis covenant");
    let genesis_utxo = UtxoEntry::new(1_500, Default::default(), 0, false, None);
    let populated = PopulatedTransaction::new(&tx, vec![genesis_utxo]);
    CovenantsContext::from_tx(&populated).expect("validate genesis covenant bindings");
    tx.outputs[0].covenant.expect("genesis output covenant").covenant_id
}

fn execute_input_with_covenants(tx: Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(&tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        EngineFlags { covenants_enabled: true },
    );
    vm.execute()
}

fn run_p2sh_transition(
    input_contract: &CompiledContract,
    function: &str,
    args: Vec<Expr<'_>>,
    output_contract: &CompiledContract,
    covenant_id: Hash,
) {
    let sigscript = input_contract.build_sig_script(function, args).expect("sigscript builds");
    let sigscript = pay_to_script_hash_signature_script(input_contract.script.clone(), sigscript).unwrap();
    let input = test_input(0, sigscript);
    let output = covenant_output(output_contract, 0, covenant_id);
    let tx = Transaction::new(1, vec![input], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = covenant_utxo(input_contract, covenant_id);
    let result = execute_input_with_covenants(tx, vec![utxo_entry], 0);
    assert!(result.is_ok(), "{function} runtime failed: {}", result.unwrap_err());
}

struct MuxFixture {
    mux_source: String,
    a_source: String,
    b_source: String,
    mux_prefix: Vec<u8>,
    mux_suffix: Vec<u8>,
    mux_hash: Vec<u8>,
    a_prefix: Vec<u8>,
    a_suffix: Vec<u8>,
    a_hash: Vec<u8>,
    b_prefix: Vec<u8>,
    b_suffix: Vec<u8>,
    b_hash: Vec<u8>,
}

fn build_mux_fixture() -> MuxFixture {
    let mux_source = load_contract_source(mux_contract_path());
    let a_source = load_contract_source(worker_a_contract_path());
    let b_source = load_contract_source(worker_b_contract_path());

    let (mux_prefix, mux_suffix, mux_hash) =
        template_parts_and_hash(&mux_source, &[vec![0x11u8; 32].into(), vec![0x21u8; 32].into(), vec![0x31u8; 32].into(), 5.into()]);
    let (a_prefix, a_suffix, a_hash) =
        template_parts_and_hash(&a_source, &[vec![0x41u8; 32].into(), vec![0x51u8; 32].into(), vec![0x61u8; 32].into(), 5.into()]);
    let (b_prefix, b_suffix, b_hash) =
        template_parts_and_hash(&b_source, &[vec![0x71u8; 32].into(), vec![0x81u8; 32].into(), vec![0x91u8; 32].into(), 5.into()]);

    MuxFixture {
        mux_source,
        a_source,
        b_source,
        mux_prefix,
        mux_suffix,
        mux_hash,
        a_prefix,
        a_suffix,
        a_hash,
        b_prefix,
        b_suffix,
        b_hash,
    }
}

#[test]
fn mux_routes_and_workers_return_to_mux() {
    let fix = build_mux_fixture();
    let state = [fix.mux_hash.clone().into(), fix.a_hash.clone().into(), fix.b_hash.clone().into(), 5.into()];
    let a_reward = 3;
    let b_gain = 5;
    let b_fee = 1;

    let mux = compile_contract(&fix.mux_source, &state, CompileOptions::default()).expect("compile mux succeeds");
    let covenant_id = populate_single_output_genesis_covenant(&mux);
    let a = compile_contract(&fix.a_source, &state, CompileOptions::default()).expect("compile A succeeds");
    let b = compile_contract(&fix.b_source, &state, CompileOptions::default()).expect("compile B succeeds");
    let mux_after_a = compile_contract(
        &fix.mux_source,
        &[fix.mux_hash.clone().into(), fix.a_hash.clone().into(), fix.b_hash.clone().into(), (5 + a_reward).into()],
        CompileOptions::default(),
    )
    .expect("compile mux after A succeeds");
    let mux_after_b = compile_contract(
        &fix.mux_source,
        &[fix.mux_hash.clone().into(), fix.a_hash.clone().into(), fix.b_hash.clone().into(), (5 + b_gain - b_fee).into()],
        CompileOptions::default(),
    )
    .expect("compile mux after B succeeds");

    run_p2sh_transition(&mux, "route", vec![0.into(), fix.a_prefix.clone().into(), fix.a_suffix.clone().into()], &a, covenant_id);
    run_p2sh_transition(&mux, "route", vec![1.into(), fix.b_prefix.clone().into(), fix.b_suffix.clone().into()], &b, covenant_id);
    run_p2sh_transition(
        &a,
        "apply",
        vec![a_reward.into(), fix.mux_prefix.clone().into(), fix.mux_suffix.clone().into()],
        &mux_after_a,
        covenant_id,
    );
    run_p2sh_transition(
        &b,
        "apply",
        vec![b_gain.into(), b_fee.into(), fix.mux_prefix.into(), fix.mux_suffix.into()],
        &mux_after_b,
        covenant_id,
    );
}
