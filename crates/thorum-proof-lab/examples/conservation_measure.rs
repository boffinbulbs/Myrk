//! Fixed synthetic workload. Timing output contains no witness or proof bytes.

use std::hint::black_box;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

use thorum_proof_lab::{Statement, prove_conservation, verify_conservation};

fn main() -> io::Result<()> {
    let statement = Statement {
        fee: 1,
        context: core::array::from_fn(|index| index as u8),
    };
    let classes = [
        ("A", [50, 50, 60, 39]),
        ("B", [u64::MAX - 1000, 0, u64::MAX - 1002, 1]),
    ];
    let mut output = BufWriter::new(io::stdout().lock());
    writeln!(output, "sample,class,operation,elapsed_ns,proof_bytes")?;
    for sample in 1..=20 {
        for (class, amounts) in classes {
            let start = Instant::now();
            let proof = black_box(prove_conservation(
                black_box(amounts),
                black_box(&statement),
            ))
            .map_err(|error| {
                io::Error::other(format!("sample {sample}, class {class}, prove: {error:?}"))
            })?;
            let prove_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            black_box(verify_conservation(
                black_box(&proof),
                black_box(&statement),
            ))
            .map_err(|error| {
                io::Error::other(format!("sample {sample}, class {class}, verify: {error:?}"))
            })?;
            let verify_ns = start.elapsed().as_nanos();
            writeln!(output, "{sample},{class},prove,{prove_ns},{}", proof.len())?;
            writeln!(
                output,
                "{sample},{class},verify,{verify_ns},{}",
                proof.len()
            )?;
        }
    }
    output.flush()
}
