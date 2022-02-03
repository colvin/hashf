use std::fs;
use std::path::PathBuf;

use clap::{App, Arg};
#[macro_use]
extern crate log;
use sha1::Sha1;
use sha2::{Digest, Sha256};

fn main() {
    let matches = App::new("hashf")
        .version(env!("CARGO_PKG_VERSION"))
        .about("rename files to their hash digests")
        .global_setting(clap::AppSettings::DeriveDisplayOrder)
        .arg(
            Arg::with_name("algorithm")
                .short("a")
                .long("algorithm")
                .takes_value(true)
                .possible_values(&["md5", "sha1", "sha256"])
                .default_value("md5")
                .help("hashing algorithm to use"),
        )
        .arg(
            Arg::with_name("no-op")
                .short("-n")
                .long("no-op")
                .help("dry run, do not modify any files"),
        )
        .arg(
            Arg::with_name("output-dir")
                .short("o")
                .long("output")
                .takes_value(true)
                .help("renamed files are moved to this directory"),
        )
        .arg(
            Arg::with_name("copy")
                .short("c")
                .long("cp")
                .help("copy files to new name instead of moving"),
        )
        .arg(
            Arg::with_name("force")
                .short("f")
                .long("force")
                .conflicts_with("no-trim")
                .help("overwrite existing files"),
        )
        .arg(
            Arg::with_name("no-trim")
                .long("no-trim")
                .conflicts_with("force")
                .help("do not delete source files when output files have collided"),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .help("supress all output"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("enable debug logging"),
        )
        .arg(
            Arg::with_name("files")
                .required(true)
                .multiple(true)
                .help("files on which to operate"),
        )
        .get_matches();

    // Exit code:
    // 0 - success
    // 1 - completed but with errors
    // 2 - fatal error
    let mut exit_code: i32 = 0;

    let log_lvl = if matches.is_present("quiet") {
        log::LevelFilter::Off
    } else if matches.is_present("verbose") {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    setup_logger(log_lvl).unwrap();

    if matches.is_present("no-op") {
        info!("no-operation mode: nothing will be changed");
    }

    if let Some(dir) = matches.value_of("output-dir") {
        let meta_res = fs::metadata(dir);
        if let Err(e) = meta_res {
            error!("bad output directory {}: {}", dir, e);
            std::process::exit(2);
        }
        let meta = meta_res.unwrap();
        if !meta.is_dir() {
            error!("bad output directory {}: not a directory", dir);
            std::process::exit(2);
        }
    }

    for file in matches.values_of("files").unwrap() {
        // Non-existent files are a non-fatal error. Log them and keep moving.
        let meta_res = fs::metadata(file);
        if let Err(e) = meta_res {
            error!("{}: {}", file, e);
            exit_code = 1;
            continue;
        }
        let meta = meta_res.unwrap();

        // Don't operate on directories.
        if meta.is_dir() {
            debug!("skipping directory {}", file);
            continue;
        }

        // Generate digest of file content.
        match fs::read(file) {
            Ok(content) => {
                let suffix = if let Some(sffx) = PathBuf::from(file).extension() {
                    Some(format!("{}", sffx.to_string_lossy()))
                } else {
                    None
                };

                let digest = match matches.value_of("algorithm").unwrap() {
                    "md5" => format!("{:x}", md5::compute(&content)),
                    "sha1" => format!("{}", Sha1::from(&content).digest()),
                    "sha256" => format!("{:x}", Sha256::digest(&content)),
                    _ => unreachable!(),
                };

                let mut new_filebuf = PathBuf::from(digest);

                let base = if let Some(dir) = matches.value_of("output-dir") {
                    Some(PathBuf::from(dir))
                } else {
                    if let Some(dir) = PathBuf::from(file).parent() {
                        Some(dir.into())
                    } else {
                        None
                    }
                };

                if let Some(dir) = base {
                    new_filebuf = dir.join(new_filebuf);
                }

                if let Some(sffx) = suffix {
                    new_filebuf = new_filebuf.with_extension(sffx);
                }

                let new_filename = new_filebuf.to_string_lossy().to_string();

                // Ignore files whose names are already correct.
                if new_filename == file {
                    debug!("skipping already correct {}", file);
                    continue;
                }

                // Ensure new file doesn't exist.
                if fs::metadata(&new_filename).is_ok() {
                    if !matches.is_present("force") {
                        if matches.is_present("no-trim") {
                            error!("already exists: {} for {}", new_filename, file);
                        } else {
                            error!(
                                "already exists: {}, trimming source: {}",
                                new_filename, file
                            );
                            if let Err(e) = fs::remove_file(file) {
                                error!("failed to remove file {}: {}", file, e);
                                exit_code = 1;
                            }
                        }
                        continue;
                    }
                }

                info!("{} <---- {}", new_filename, file);

                // Iterate before we change anything if we're in no-op mode.
                if matches.is_present("no-op") {
                    continue;
                }

                // We always copy, because renaming doesn't work across filesystems.  In copy
                // mode, we just don't remove afterwards.
                if let Err(e) = fs::copy(file, &new_filename) {
                    error!("failed to copy to {}: {}", new_filename, e);
                    exit_code = 1;
                    continue;
                }
                if !matches.is_present("copy") {
                    if let Err(e) = fs::remove_file(file) {
                        error!("failed to remove {}: {}", file, e);
                        exit_code = 1;
                        continue;
                    }
                }
            }
            Err(e) => {
                error!("{}: {}", file, e);
                exit_code = 1;
            }
        }
    }

    std::process::exit(exit_code);
}

fn setup_logger(lvl: log::LevelFilter) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} {} {:^5} -- {}",
                record.target(),
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                record.level(),
                message
            ))
        })
        .level(lvl)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}
