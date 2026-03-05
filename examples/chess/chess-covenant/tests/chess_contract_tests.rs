use std::fs;

use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

use chess_covenant::example_contract_path;

fn load_contract_source() -> String {
    let path = example_contract_path();
    fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn default_constructor_args() -> Vec<Expr<'static>> {
    let standard_board: Vec<u8> = vec![
        0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, // y = 0 (white)
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // y = 1 (white pawns)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // y = 2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // y = 3
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // y = 4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // y = 5
        0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, // y = 6 (black pawns)
        0x0c, 0x0a, 0x0b, 0x0d, 0x0e, 0x0b, 0x0a, 0x0c, // y = 7 (black)
    ];

    vec![Expr::bytes(vec![1u8; 32]), Expr::bytes(vec![2u8; 32]), Expr::bytes(standard_board)]
}

#[test]
fn chess_contract_compiles_with_singleton_transition_entrypoint() {
    let source = load_contract_source();
    let compiled =
        compile_contract(&source, &default_constructor_args(), CompileOptions::default()).expect("chess covenant should compile");

    assert!(compiled.without_selector, "covenant declarations should compile without selector");
    assert_eq!(compiled.abi.len(), 1);
    assert_eq!(compiled.abi[0].name, "play");
    assert!(compiled.ast.functions.iter().any(|f| f.name == "__covenant_policy_play" && !f.entrypoint));
    assert!(compiled.ast.functions.iter().any(|f| f.name == "play" && f.entrypoint));
}

#[test]
fn chess_contract_requires_expected_constructor_arg_shape() {
    let source = load_contract_source();
    let err = compile_contract(&source, &[Expr::bytes(vec![1u8; 32])], CompileOptions::default())
        .expect_err("constructor should require all arguments");

    assert!(err.to_string().contains("constructor"));
}
