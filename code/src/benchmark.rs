use std::{
    fs::{self, File},
    hint::black_box,
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

#[derive(Clone, Copy, Debug)]
pub struct BenchmarkOptions {
    pub warmup: usize,
    pub repetitions: usize,
    pub inner_iterations: usize,
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            warmup: 20,
            repetitions: 100,
            inner_iterations: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Measurement {
    pub scheme: String,
    pub phase: String,
    pub axis_name: String,
    pub axis_value: usize,
    pub samples_ms: Vec<f64>,
    pub summary: SummaryStatistics,
}

#[derive(Clone, Copy, Debug)]
pub struct SummaryStatistics {
    pub mean_ms: f64,
    pub median_ms: f64,
    pub stddev_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub ci95_low_ms: f64,
    pub ci95_high_ms: f64,
}

pub fn measure<T>(
    scheme: &str,
    phase: &str,
    axis_name: &str,
    axis_value: usize,
    options: BenchmarkOptions,
    mut operation: impl FnMut() -> T,
) -> Measurement {
    assert!(options.repetitions > 1);
    assert!(options.inner_iterations > 0);
    for _ in 0..options.warmup {
        for _ in 0..options.inner_iterations {
            black_box(operation());
        }
    }

    let mut samples_ms = Vec::with_capacity(options.repetitions);
    for _ in 0..options.repetitions {
        let start = Instant::now();
        for _ in 0..options.inner_iterations {
            black_box(operation());
        }
        samples_ms.push(start.elapsed().as_secs_f64() * 1_000.0 / options.inner_iterations as f64);
    }
    let summary = summarize(&samples_ms);
    Measurement {
        scheme: scheme.to_owned(),
        phase: phase.to_owned(),
        axis_name: axis_name.to_owned(),
        axis_value,
        samples_ms,
        summary,
    }
}

pub fn summarize(samples: &[f64]) -> SummaryStatistics {
    assert!(samples.len() > 1);
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let count = sorted.len() as f64;
    let mean = sorted.iter().sum::<f64>() / count;
    let median = if sorted.len() % 2 == 0 {
        let right = sorted.len() / 2;
        (sorted[right - 1] + sorted[right]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    let variance = sorted
        .iter()
        .map(|sample| (sample - mean).powi(2))
        .sum::<f64>()
        / (count - 1.0);
    let stddev = variance.sqrt();
    let half_width = 1.96 * stddev / count.sqrt();
    SummaryStatistics {
        mean_ms: mean,
        median_ms: median,
        stddev_ms: stddev,
        min_ms: sorted[0],
        max_ms: sorted[sorted.len() - 1],
        ci95_low_ms: mean - half_width,
        ci95_high_ms: mean + half_width,
    }
}

pub fn write_raw_csv(path: &Path, measurements: &[Measurement]) -> std::io::Result<()> {
    ensure_parent(path)?;
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(
        writer,
        "scheme,phase,axis_name,axis_value,sample,elapsed_ms"
    )?;
    for measurement in measurements {
        for (sample, elapsed) in measurement.samples_ms.iter().enumerate() {
            writeln!(
                writer,
                "\"{}\",\"{}\",\"{}\",{},{},{:.9}",
                measurement.scheme,
                measurement.phase,
                measurement.axis_name,
                measurement.axis_value,
                sample + 1,
                elapsed
            )?;
        }
    }
    Ok(())
}

pub fn write_summary_csv(path: &Path, measurements: &[Measurement]) -> std::io::Result<()> {
    ensure_parent(path)?;
    let mut writer = BufWriter::new(File::create(path)?);
    writeln!(writer, "scheme,phase,axis_name,axis_value,samples,mean_ms,median_ms,stddev_ms,min_ms,max_ms,ci95_low_ms,ci95_high_ms")?;
    for measurement in measurements {
        let summary = measurement.summary;
        writeln!(
            writer,
            "\"{}\",\"{}\",\"{}\",{},{},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9},{:.9}",
            measurement.scheme,
            measurement.phase,
            measurement.axis_name,
            measurement.axis_value,
            measurement.samples_ms.len(),
            summary.mean_ms,
            summary.median_ms,
            summary.stddev_ms,
            summary.min_ms,
            summary.max_ms,
            summary.ci95_low_ms,
            summary.ci95_high_ms,
        )?;
    }
    Ok(())
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_uses_sample_standard_deviation_and_ci95() {
        let summary = summarize(&[1.0, 2.0, 3.0, 4.0]);
        assert!((summary.mean_ms - 2.5).abs() < 1e-12);
        assert!((summary.median_ms - 2.5).abs() < 1e-12);
        assert!((summary.stddev_ms - 1.290_994_448_735_805_6).abs() < 1e-12);
        assert!(summary.ci95_low_ms < summary.mean_ms);
        assert!(summary.ci95_high_ms > summary.mean_ms);
    }
}
