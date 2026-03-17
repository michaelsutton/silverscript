use std::env;
use std::time::Instant;

use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

#[derive(Clone, Copy)]
enum ProbeMode {
    EmptyIf,
    BoardIf,
    CounterOnly,
    CounterUnderIf,
    TwoCountersUnderIf,
    IfElseTwoUpdates,
    NestedIfUpdate,
    CounterPlusMathUnderIf,
    RequireInLoop,
}

impl ProbeMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "empty-if" => Some(Self::EmptyIf),
            "board-if" => Some(Self::BoardIf),
            "counter-only" => Some(Self::CounterOnly),
            "counter-if" => Some(Self::CounterUnderIf),
            "two-counters-if" => Some(Self::TwoCountersUnderIf),
            "if-else-two" => Some(Self::IfElseTwoUpdates),
            "nested-if" => Some(Self::NestedIfUpdate),
            "counter-math-if" => Some(Self::CounterPlusMathUnderIf),
            "require-in-loop" => Some(Self::RequireInLoop),
            _ => None,
        }
    }

    fn body(self) -> &'static str {
        match self {
            Self::EmptyIf => {
                r#"
        if (i >= 0) {
        }
"#
            }
            Self::BoardIf => {
                r#"
        if (OpBin2Num(board[i]) == 0) {
        }
"#
            }
            Self::CounterOnly => {
                r#"
        zero_count = zero_count + 1;
"#
            }
            Self::CounterUnderIf => {
                r#"
        if (OpBin2Num(board[i]) == 0) {
            zero_count = zero_count + 1;
        }
"#
            }
            Self::TwoCountersUnderIf => {
                r#"
        if (OpBin2Num(board[i]) == 0) {
            zero_count = zero_count + 1;
        } else {
            one_count = one_count + 1;
        }
"#
            }
            Self::IfElseTwoUpdates => {
                r#"
        if ((i % 2) == 0) {
            sum = sum + i;
            last = i;
        } else {
            sum = sum - i;
            last = -i;
        }
"#
            }
            Self::NestedIfUpdate => {
                r#"
        if (OpBin2Num(board[i]) == 0) {
            if ((i % 3) == 0) {
                zero_count = zero_count + 2;
            } else {
                zero_count = zero_count + 1;
            }
        }
"#
            }
            Self::CounterPlusMathUnderIf => {
                r#"
        if (OpBin2Num(board[i]) == 0) {
            zero_count = zero_count + 1;
            acc = acc + (i * i) - i;
        } else {
            acc = acc + i;
        }
"#
            }
            Self::RequireInLoop => {
                r#"
        // bounded checks that still read both args and locals
        require(i >= 0);
        require(OpBin2Num(board[i]) >= 0);
        acc = acc + i;
"#
            }
        }
    }

    fn uses_counter(self) -> bool {
        matches!(
            self,
            Self::CounterOnly | Self::CounterUnderIf | Self::TwoCountersUnderIf | Self::NestedIfUpdate | Self::CounterPlusMathUnderIf
        )
    }

    fn name(self) -> &'static str {
        match self {
            Self::EmptyIf => "empty-if",
            Self::BoardIf => "board-if",
            Self::CounterOnly => "counter-only",
            Self::CounterUnderIf => "counter-if",
            Self::TwoCountersUnderIf => "two-counters-if",
            Self::IfElseTwoUpdates => "if-else-two",
            Self::NestedIfUpdate => "nested-if",
            Self::CounterPlusMathUnderIf => "counter-math-if",
            Self::RequireInLoop => "require-in-loop",
        }
    }
}

fn source_for_loop_bound(bound: usize, mode: ProbeMode) -> String {
    let mut decls = String::new();
    if mode.uses_counter() {
        decls.push_str("        int zero_count = 0;\n");
    }
    if matches!(mode, ProbeMode::TwoCountersUnderIf) {
        decls.push_str("        int one_count = 0;\n");
    }
    if matches!(mode, ProbeMode::IfElseTwoUpdates) {
        decls.push_str("        int sum = 0;\n");
        decls.push_str("        int last = 0;\n");
    }
    if matches!(mode, ProbeMode::CounterPlusMathUnderIf | ProbeMode::RequireInLoop) {
        decls.push_str("        int acc = 0;\n");
    }

    let final_check = if matches!(mode, ProbeMode::TwoCountersUnderIf) {
        "        require(zero_count + one_count >= 0);\n"
    } else if matches!(mode, ProbeMode::IfElseTwoUpdates) {
        "        require(sum + last >= -1000000);\n"
    } else if matches!(mode, ProbeMode::CounterPlusMathUnderIf | ProbeMode::RequireInLoop) {
        "        require(acc >= -1000000);\n"
    } else if mode.uses_counter() {
        "        require(zero_count >= 0);\n"
    } else {
        "        require(true);\n"
    };
    format!(
        r#"
pragma silverscript ^0.1.0;

contract Sweep(byte[64] init_board) {{
    byte[64] board = init_board;

    entrypoint function main() {{
{decls}
        for (i, 0, {bound}, {bound}) {{
{body}
        }}
{final_check}
    }}
}}
"#,
        body = mode.body(),
        decls = decls,
    )
}

fn main() {
    let mut mode = ProbeMode::CounterUnderIf;
    let mut bounds = Vec::new();
    for arg in env::args().skip(1) {
        if let Some(parsed_mode) = ProbeMode::parse(&arg) {
            mode = parsed_mode;
        } else {
            bounds.push(arg.parse().expect("bounds must be integers"));
        }
    }
    let bounds = if bounds.is_empty() { vec![1, 2, 4, 8, 16, 24, 32, 40, 48, 56, 64] } else { bounds };

    for bound in bounds {
        let source = source_for_loop_bound(bound, mode);
        let args = [Expr::bytes(vec![0u8; 64])];
        let started = Instant::now();
        match compile_contract(&source, &args, CompileOptions::default()) {
            Ok(compiled) => {
                let elapsed_ms = started.elapsed().as_millis();
                let per = (compiled.script.len() as f64) / (bound as f64);
                println!(
                    "mode={} loop_bound={bound} script_len={} bytes_per_iter={:.1} compile_ms={elapsed_ms}",
                    mode.name(),
                    compiled.script.len(),
                    per
                );
            }
            Err(err) => {
                let elapsed_ms = started.elapsed().as_millis();
                println!("mode={} loop_bound={bound} compile_error={err} compile_ms={elapsed_ms}", mode.name());
            }
        }
    }
}
