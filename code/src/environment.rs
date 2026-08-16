use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    process::Command,
};

#[derive(Clone, Debug)]
pub struct EnvironmentRecord {
    pub seed: u64,
    pub warmup: usize,
    pub repetitions: usize,
    pub inner_iterations: usize,
}

pub fn write_environment(path: &Path, record: &EnvironmentRecord) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(writer, "OS: {}", env::consts::OS)?;
    writeln!(writer, "Architecture: {}", env::consts::ARCH)?;
    writeln!(
        writer,
        "CPU model: {}",
        env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unknown".to_owned())
    )?;
    writeln!(
        writer,
        "Logical core count: {}",
        std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
    )?;
    writeln!(writer, "Physical memory bytes: {}", physical_memory())?;
    writeln!(
        writer,
        "Compiler: {}",
        command_output("rustc", &["--version"])
    )?;
    writeln!(
        writer,
        "Compile flags: release; opt-level=3; thin LTO; codegen-units=1"
    )?;
    writeln!(writer, "Arkworks: v0.5.0 local source tree")?;
    writeln!(writer, "mcl: N/A (Arkworks backend selected)")?;
    writeln!(
        writer,
        "OpenSSL: {}",
        command_output("openssl", &["version"])
    )?;
    writeln!(writer, "Pairing curve: BLS12-381 Type-3")?;
    writeln!(writer, "Security level: approximately 128 bits")?;
    writeln!(writer, "Benchmark thread count: 1")?;
    writeln!(writer, "Random seed: {}", record.seed)?;
    writeln!(writer, "Warm-up executions: {}", record.warmup)?;
    writeln!(writer, "Timed repetitions: {}", record.repetitions)?;
    writeln!(
        writer,
        "Operations averaged per timed sample: {}",
        record.inner_iterations
    )?;
    writeln!(writer, "Git commit: {}", git_commit())?;
    Ok(())
}

fn physical_memory() -> String {
    if env::consts::OS == "windows" {
        let script = "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory";
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output();
        if let Ok(output) = output {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_owned();
            }
        }
    }
    "unknown".to_owned()
}

fn git_commit() -> String {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "N/A (not a git worktree)".to_owned(),
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "not found".to_owned(),
    }
}
