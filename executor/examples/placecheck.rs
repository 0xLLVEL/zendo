fn main() {
    match zendo_core::place_hint() {
        Ok(Some(id)) => println!("place hint: {id}"),
        Ok(None) => println!("place hint: none (no transition in the log tail)"),
        Err(why) => println!("place refused: {why}"),
    }
}
