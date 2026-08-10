//! Disassemble a script from the command line.
//!
//!     cargo run --example disasm -- 76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac
//!
//! With no argument, walks a sample of the mainnet vectors in src/examples/.

use bitcoin_tools_web_server::types::transactions::script::Script;

fn show(hex: &str) {
    let script = match Script::from_hex(hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{hex}: {e}");
            return;
        }
    };
    let (steps, err) = script.disassemble();

    println!("\n{} bytes  kind={}", script.len(), script.kind());
    println!("  {}", script.to_asm());
    for step in &steps {
        let op = step.instruction.opcode();
        let detail = match step.instruction.data() {
            Some(d) => format!("push {} bytes", d.len()),
            None => op.describe().unwrap_or("").to_string(),
        };
        println!(
            "  {:>4}  {:02x}  {:<22} {:<11} {}",
            step.offset,
            op.to_u8(),
            op.to_string(),
            format!("{:?}", op.category()),
            detail
        );
    }
    if let Some(e) = err {
        println!("  !! {e}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        for a in &args {
            show(a);
        }
        return;
    }

    for hex in [
        "76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac",
        "a914d6763da611b0566f4436b86ba159de02a8f9190287",
        "0014275b468073affad6c1b2833d026416ec07392b7f",
        "512050a50a97836860d6a71463ac8e244751f2db62dd02348470f27158c927a439cc",
        "5121034d31a1a1622a3c3902370d0f47b531e2b16b1f90d13e86a707dfb4114603f19451ae",
        "7605aabb", // deliberately truncated
    ] {
        show(hex);
    }
}
