use anyhow::{anyhow, bail, Context};
use flate2::Status;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Autodetects the root git directory by attempting to find the .git
/// directory inside it and traversing the directory structure upwards
fn find_git_root() -> anyhow::Result<PathBuf> {
    let current_dir = std::env::current_dir()?;

    let mut git_root: &Path = &current_dir;
    loop {
        match std::fs::metadata(git_root.join(".git")) {
            Ok(m) if m.is_dir() => {
                break;
            }
            Ok(_) | Err(_) => {
                // Try one level up
                git_root = git_root
                    .parent()
                    .ok_or_else(|| anyhow!("Failed to auto-detect root git directory"))?;
            }
        };
    }

    Ok(git_root.to_path_buf())
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Sha1(String);

impl AsRef<str> for Sha1 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Sha1 {
    type Error = anyhow::Error;
    fn try_from(val: &str) -> anyhow::Result<Self> {
        const SHA1_LEN: usize = 40;
        if val.len() != SHA1_LEN {
            bail!("Unexpected length for sha1: {}", val.len());
        }
        let is_alphanumeric = val.chars().all(|c| c.is_alphanumeric());
        if !is_alphanumeric {
            bail!("value is not alphanumeric: {}", val);
        }

        Ok(Sha1(val.to_string()))
    }
}

impl TryFrom<String> for Sha1 {
    type Error = anyhow::Error;
    fn try_from(val: String) -> anyhow::Result<Self> {
        const SHA1_LEN: usize = 40;
        if val.len() != SHA1_LEN {
            bail!("Unexpected length for sha1: {}", val.len());
        }
        let is_alphanumeric = val.chars().all(|c| c.is_alphanumeric());
        if !is_alphanumeric {
            bail!("value is not alphanumeric: {}", val);
        }

        Ok(Sha1(val))
    }
}

struct GitBlob(Vec<u8>);

enum GitObject {
    Blob(GitBlob),
}

fn parse_blob_object(data: &[u8]) -> anyhow::Result<GitObject> {
    Ok(GitObject::Blob(GitBlob(data.to_vec())))
}

fn parse_object(data: &[u8]) -> anyhow::Result<GitObject> {
    let header: Vec<_> = data.iter().take_while(|b| **b != 0).map(|b| *b).collect();

    let header = std::str::from_utf8(&header)?;
    let (ty, length): (&str, usize) = {
        let mut iter = header.split_whitespace();
        (
            iter.next().ok_or(anyhow!("Header is empty"))?,
            iter.next().ok_or(anyhow!("No length in header"))?.parse()?,
        )
    };

    let (_, contents) = data.split_at(header.len() + 1);
    if length != contents.len() {
        bail!("Missing contents for git object. Header indicates {length} bytes, but only {} are available", contents.len());
    }

    match ty {
        "blob" => parse_blob_object(contents),
        "commit" => unimplemented!(),
        t => Err(anyhow!("Invalid git object type found: {t}")),
    }
}

fn read_object(git_root: &Path, object_sha: &Sha1) -> anyhow::Result<GitObject> {
    let (sha_dir, sha_file_name) = object_sha.as_ref().split_at(2);
    let contents = fs::read(
        git_root
            .join(".git/objects")
            .join(sha_dir)
            .join(sha_file_name),
    )
    .with_context(|| format!("Unable to read object {object_sha:?}"))?;

    let mut dec = flate2::Decompress::new(true);
    let mut decompressed = vec![];

    loop {
        let in_offset = dec.total_in() as usize;

        const BLOCK_SIZE: usize = 128;
        decompressed.reserve_exact(BLOCK_SIZE);

        let status = dec.decompress_vec(
            &contents[in_offset..],
            &mut decompressed,
            flate2::FlushDecompress::Sync,
        )?;

        if status == Status::StreamEnd {
            break;
        } else if status == Status::BufError {
            anyhow::bail!("zlib decompression error");
        }
    }

    parse_object(&decompressed)
}

/// Initializes a new git repository in the current directory
fn init_dir() -> anyhow::Result<()> {
    if let Ok(root) = find_git_root() {
        bail!("Looks like there is already an existing git repository at: {root:?}");
    }
    fs::create_dir(".git")?;
    fs::create_dir(".git/objects")?;
    fs::create_dir(".git/refs")?;
    fs::write(".git/HEAD", "ref: refs/heads/master\n")?;
    println!("Initialized git directory");
    Ok(())
}

/// Prints the contents of a git blob
fn cat_file(args: &[String]) -> anyhow::Result<()> {
    // let pretty_print = args.iter().find(|a| *a == "-p").is_some();

    let object_sha: Sha1 = args
        .iter()
        .skip_while(|arg| arg.starts_with("-"))
        .next()
        .ok_or(anyhow!("cat-file requires argument \"<obj-hash>\""))
        .and_then(|string| {
            let s: &str = &string;
            s.try_into()
        })?;

    let root = find_git_root()?;

    let object = read_object(&root, &object_sha)?;
    match object {
        GitObject::Blob(blob) => {
            print!("{}", std::str::from_utf8(&blob.0)?);
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        bail!("Please, provide a command to execute");
    }

    if args[1] == "init" {
        init_dir()?
    } else if args[1] == "cat-file" {
        cat_file(&args[2..])?
    } else {
        println!("unknown command: {}", args[1])
    };
    Ok(())
}
