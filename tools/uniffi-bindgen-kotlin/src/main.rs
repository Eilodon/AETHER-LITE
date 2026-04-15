use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use uniffi_bindgen::bindings::TargetLanguage;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("--") {
        args.remove(0);
    }
    if args.len() != 3 {
        bail!("usage: uniffi-bindgen-kotlin <udl> <out-dir> <crate-name>");
    }

    let udl = Utf8PathBuf::from(&args[0]);
    let out_dir = Utf8PathBuf::from(&args[1]);
    let crate_name = args[2].as_str();

    uniffi_bindgen::generate_bindings(
        &udl,
        None::<&camino::Utf8Path>,
        vec![TargetLanguage::Kotlin],
        Some(&out_dir),
        None::<&camino::Utf8Path>,
        Some(crate_name),
        false,
    )
    .with_context(|| format!("failed to generate Kotlin bindings from {}", udl))?;

    Ok(())
}
