fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "capsule/guest/bootstrap/v1/bootstrap.proto",
                "capsule/guest/v1/operational.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
