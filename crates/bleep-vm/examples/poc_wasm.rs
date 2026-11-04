use bleep_vm::engines::WasmEngineAdapter;
use bleep_vm::execution::execution_context::{BlockEnv, ExecutionContext, TxEnv};
use bleep_vm::router::vm_router::Engine;
use bleep_vm::types::ChainId;
use wasm_encoder::{
    CodeSection, ConstExpr, DataSection, ExportKind, ExportSection, Function, FunctionSection,
    ImportSection, Instruction, MemorySection, MemoryType, Module, TypeSection, ValType,
};

fn context() -> ExecutionContext {
    ExecutionContext::new(
        BlockEnv::default(),
        TxEnv::default(),
        100_000,
        ChainId::Bleep,
        uuid::Uuid::new_v4(),
        16,
    )
}

fn infinite_loop_wasm() -> Vec<u8> {
    let mut types = TypeSection::new();
    types.function([ValType::I32], []);
    let mut functions = FunctionSection::new();
    functions.function(0);
    let mut exports = ExportSection::new();
    exports.export("execute", ExportKind::Func, 0);
    let mut function = Function::new([]);
    function.instruction(&Instruction::Loop(wasm_encoder::BlockType::Empty));
    function.instruction(&Instruction::Br(0));
    function.instruction(&Instruction::End);
    function.instruction(&Instruction::End);
    let mut code = CodeSection::new();
    code.function(&function);
    let mut module = Module::new();
    module
        .section(&types)
        .section(&functions)
        .section(&exports)
        .section(&code);
    module.finish()
}

fn storage_writer_wasm() -> Vec<u8> {
    let mut types = TypeSection::new();
    types.function([ValType::I32, ValType::I32, ValType::I32, ValType::I32], []);
    types.function([ValType::I32], []);
    let mut imports = ImportSection::new();
    imports.import(
        "bleep",
        "storage_write",
        wasm_encoder::EntityType::Function(0),
    );
    let mut functions = FunctionSection::new();
    functions.function(1);
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: 1,
        maximum: Some(1),
        memory64: false,
        shared: false,
    });
    let mut exports = ExportSection::new();
    exports.export("memory", ExportKind::Memory, 0);
    exports.export("execute", ExportKind::Func, 1);
    let mut function = Function::new([]);
    for value in [0, 32, 32, 32] {
        function.instruction(&Instruction::I32Const(value));
    }
    function.instruction(&Instruction::Call(0));
    function.instruction(&Instruction::End);
    let mut code = CodeSection::new();
    code.function(&function);
    let mut data = DataSection::new();
    data.active(0, &ConstExpr::i32_const(0), [1u8; 32]);
    data.active(0, &ConstExpr::i32_const(32), [2u8; 32]);
    let mut module = Module::new();
    module
        .section(&types)
        .section(&imports)
        .section(&functions)
        .section(&memories)
        .section(&exports)
        .section(&code)
        .section(&data);
    module.finish()
}

#[tokio::main]
async fn main() {
    let engine = WasmEngineAdapter::new();
    if std::env::var_os("POC_HANG").is_some() {
        let result = engine
            .execute(&context(), &infinite_loop_wasm(), &[], 100_000)
            .await;
        println!("HANG reverted: {}", result.is_err());
        return;
    }

    let storage_result = engine
        .execute(&context(), &storage_writer_wasm(), &[], 100_000)
        .await;
    println!(
        "C-05a state_diff non-empty: {}",
        storage_result.is_ok_and(|result| !result.state_diff.storage.is_empty())
    );

    let deploy_result = engine
        .deploy(&context(), &[0, 1, 2, 3], &[], 100_000, None)
        .await;
    println!(
        "C-05b invalid deployment rejected: {}",
        deploy_result.is_err()
    );
}
