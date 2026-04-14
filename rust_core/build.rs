// rust_core/build.rs
fn main() {
    // Generate FFI scaffolding code from the UDL interface definition
    uniffi::generate_scaffolding("./src/aether.udl").unwrap();
}
