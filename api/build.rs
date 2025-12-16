fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../proto/relay.proto");
    tonic_prost_build::compile_protos("../proto/relay.proto")?;
    Ok(())
}
