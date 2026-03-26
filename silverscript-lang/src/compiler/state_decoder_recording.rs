use crate::ast::FunctionAst;

use super::{
    CompiledStateDecoderInfo, CompiledStateFieldLayout, CompiledStateLayoutSchema, CompiledValidationArgCapture,
    CompiledValidationCall, StructFieldSpec, ValidationBuiltinKind, ValidationObservedField,
};

#[derive(Debug, Default)]
pub struct StateDecoderRecorder {
    entrypoints: Vec<StagedStateDecoderEntrypoint>,
}

impl StateDecoderRecorder {
    pub fn begin_entrypoint(&mut self, function: &FunctionAst<'_>) {
        self.entrypoints.push(StagedStateDecoderEntrypoint {
            name: function.name.clone(),
            bytecode_start: None,
            validation_calls: Vec::new(),
        });
    }

    pub fn finish_entrypoint(&mut self, _script_len: usize) {}

    pub fn set_entrypoint_start(&mut self, name: &str, bytecode_start: usize) {
        if let Some(entrypoint) = self.entrypoints.iter_mut().find(|entrypoint| entrypoint.name == name) {
            entrypoint.bytecode_start = Some(bytecode_start);
        }
    }

    pub fn record_validation_call(&mut self, builtin_kind: ValidationBuiltinKind, captures: Vec<StagedValidationArgCapture>) {
        let Some(entrypoint) = self.entrypoints.last_mut() else {
            return;
        };
        entrypoint.validation_calls.push(StagedValidationCall { builtin_kind, captures });
    }

    pub fn into_info(self) -> CompiledStateDecoderInfo {
        let mut info = CompiledStateDecoderInfo::default();

        for entrypoint in self.entrypoints {
            let bytecode_start = entrypoint.bytecode_start.unwrap_or(0);
            for call in entrypoint.validation_calls {
                let captures = call
                    .captures
                    .into_iter()
                    .map(|capture| {
                        let state_layout_id = capture.layout.map(|layout| {
                            info.state_layouts.iter().position(|existing| existing == &layout).unwrap_or_else(|| {
                                info.state_layouts.push(layout.clone());
                                info.state_layouts.len().saturating_sub(1)
                            })
                        });
                        CompiledValidationArgCapture {
                            bytecode_offset: capture.bytecode_offset + bytecode_start,
                            field: capture.field,
                            state_layout_id,
                        }
                    })
                    .collect();
                info.validation_calls.push(CompiledValidationCall { builtin_kind: call.builtin_kind, captures });
            }
        }

        info
    }
}

#[derive(Debug)]
struct StagedStateDecoderEntrypoint {
    name: String,
    bytecode_start: Option<usize>,
    validation_calls: Vec<StagedValidationCall>,
}

#[derive(Debug, Clone)]
pub struct StagedValidationArgCapture {
    bytecode_offset: usize,
    field: ValidationObservedField,
    layout: Option<CompiledStateLayoutSchema>,
}

impl StagedValidationArgCapture {
    pub fn top_of_stack(bytecode_offset: usize, field: ValidationObservedField) -> Self {
        Self { bytecode_offset, field, layout: None }
    }

    pub fn encoded_state(bytecode_offset: usize, layout_fields: &[StructFieldSpec]) -> Self {
        Self {
            bytecode_offset,
            field: ValidationObservedField::EncodedState,
            layout: Some(CompiledStateLayoutSchema {
                fields: layout_fields
                    .iter()
                    .map(|field| CompiledStateFieldLayout { name: field.name.clone(), type_name: field.type_ref.type_name() })
                    .collect(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct StagedValidationCall {
    builtin_kind: ValidationBuiltinKind,
    captures: Vec<StagedValidationArgCapture>,
}
