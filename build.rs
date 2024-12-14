fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute(".", "#[derive(Hash, Eq, PartialOrd, Ord)]")
        .compile(&["proto/rumi.proto"], &["proto"])?;
    Ok(())
}
