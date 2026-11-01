#![forbid(unsafe_code)]
use kova_state_journal::Journal;
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
fn barrier(byte: u8) -> io::Result<()> {
    io::stdout().write_all(&[byte])?;
    io::stdout().flush()?;
    let mut ack = [0];
    io::stdin().read_exact(&mut ack)?;
    if ack != [b'+'] {
        return Err(io::Error::other("Invalid control acknowledgement"));
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("KOVA_JOURNAL_GATE").as_deref() != Ok("reviewed-external-resource-admission") {
        return Err("External admission required".into());
    }
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or("Missing mode")?;
    let path = PathBuf::from(args.next().ok_or("Missing directory")?);
    if args.next().is_some() {
        return Err("Unexpected argument".into());
    }
    let mut journal = Journal::open(&path)?;
    if mode == "read" {
        io::stdout().write_all(&journal.head().generation.to_be_bytes())?;
        io::stdout().write_all(&journal.head().payload)?;
    } else if mode == "write" {
        let mut a = journal.begin(0, b"B")?;
        barrier(b'C')?;
        a.write()?;
        barrier(b'W')?;
        a.sync()?;
        barrier(b'S')?;
        a.publish()?;
        barrier(b'P')?;
        a.finish()?;
        barrier(b'F')?;
    } else if mode == "append" {
        let generation = journal.head().generation;
        let mut a = journal.begin(generation, b"C")?;
        a.write()?;
        a.sync()?;
        a.publish()?;
        a.finish()?;
    } else {
        return Err("Unknown mode".into());
    }
    Ok(())
}
