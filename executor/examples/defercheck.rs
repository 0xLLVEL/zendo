fn main() {
    match zendo_core::compile_deferred("print('hi')") {
        Ok(b) => println!("deferred chunk ok: {} bytes", b.len()),
        Err(e) => println!("deferred chunk FAILED: {e}"),
    }
}
