use anyhow::{anyhow, bail, Context};
use sha1::Digest;

use std::env;
use std::fs;
use std::os::unix::prelude::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

mod zlib;

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
struct GitSha1(String);

impl AsRef<str> for GitSha1 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for GitSha1 {
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

        Ok(GitSha1(val.to_string()))
    }
}

impl TryFrom<String> for GitSha1 {
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

        Ok(GitSha1(val))
    }
}

#[derive(Debug, Clone)]
struct GitBlob(Vec<u8>);

#[derive(Debug, Clone)]
struct GitTreeEntry {
    mode: u32,
    name: String,
    sha1: GitSha1,
}

#[derive(Debug, Clone)]
struct GitTree(Vec<GitTreeEntry>);

impl GitTree {
    fn new() -> Self {
        Self(vec![])
    }
}

#[derive(Debug, Clone)]
enum GitObject {
    Blob(GitBlob),
    Tree(GitTree),
}

fn parse_blob_object(data: &[u8]) -> anyhow::Result<GitObject> {
    Ok(GitObject::Blob(GitBlob(data.to_vec())))
}

trait MyIter: Iterator<Item = u8> + Clone {}

fn parse_tree_object(data: &[u8]) -> anyhow::Result<GitObject> {
    let mut entries = vec![];
    let mut offset = 0;

    loop {
        if offset >= data.len() {
            break;
        }

        let mode: Vec<u8> = data
            .iter()
            .cloned()
            .skip(offset)
            .take_while(|b| *b != b' ')
            .collect();
        offset += mode.len() + 1;
        let mode = u32::from_str_radix(std::str::from_utf8(&mode)?, 8)?;

        let name: Vec<u8> = data
            .iter()
            .cloned()
            .skip(offset)
            .take_while(|b| *b != 0)
            .collect();
        let name = std::str::from_utf8(&name)?.to_string();
        offset += name.bytes().count() + 1;

        const HASH_LEN: usize = 20;
        let hash: Vec<u8> = data.iter().cloned().skip(offset).take(HASH_LEN).collect();
        let hash: GitSha1 = hex::encode(hash).try_into()?;

        offset += HASH_LEN;
        entries.push(GitTreeEntry {
            name,
            sha1: hash,
            mode,
        });
    }

    Ok(GitObject::Tree(GitTree(entries)))
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
        "tree" => parse_tree_object(contents),
        "commit" => unimplemented!(),
        t => Err(anyhow!("Invalid git object type found: {t}")),
    }
}

fn read_object(git_root: &Path, object_sha: &GitSha1) -> anyhow::Result<GitObject> {
    let (sha_dir, sha_file_name) = object_sha.as_ref().split_at(2);
    let contents = fs::read(
        git_root
            .join(".git/objects")
            .join(sha_dir)
            .join(sha_file_name),
    )
    .with_context(|| format!("Unable to read object {object_sha:?}"))?;

    let decompressed = zlib::decompress(&contents)?;
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

/// Prints the contents of a git object
fn cat_file(args: &[String]) -> anyhow::Result<()> {
    // let pretty_print = args.iter().find(|a| *a == "-p").is_some();

    let object_sha: GitSha1 = args
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
        GitObject::Tree(tree) => {
            for entry in &tree.0 {
                println!("{}", entry.name);
            }
        }
    }

    Ok(())
}

/// Prints the contents of a tree
fn ls_tree(args: &[String]) -> anyhow::Result<()> {
    let name_only = args.iter().find(|a| *a == "--name-only").is_some();

    let object_sha: GitSha1 = args
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
        GitObject::Tree(tree) => {
            if name_only {
                for entry in &tree.0 {
                    println!("{}", entry.name);
                }
            } else {
                println!("{tree:?}");
            }
        }
        _ => {
            bail!("Object is not a tree");
        }
    }

    Ok(())
}

fn write_blob_object(path: &Path, actually_write: bool) -> anyhow::Result<GitSha1> {
    let root = find_git_root()?;

    let contents = std::fs::read(path).context("Unable to read source file for object")?;
    let content_length = format!("{}", contents.len());
    let mut serialized = vec![b'b', b'l', b'o', b'b', b' '];
    serialized.extend(content_length.bytes());
    serialized.push(0);
    serialized.extend(contents);

    let mut hasher = sha1::Sha1::new();
    hasher.update(&serialized);
    let hash = hasher.finalize();
    let hash = GitSha1(hex::encode(hash));

    if actually_write {
        let (sha_dir, sha_file_name) = hash.as_ref().split_at(2);
        let object_path = root
            .join(".git")
            .join("objects")
            .join(sha_dir)
            .join(sha_file_name);
        let compressed = zlib::compress(&serialized)?;
        fs::create_dir_all(object_path.parent().unwrap())?;
        fs::write(object_path, compressed)?;
    }

    Ok(hash)
}

fn write_tree_object(directory: &Path) -> anyhow::Result<GitSha1> {
    let mut tree = GitTree::new();

    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("Invalid file name!"))?;
        if name == ".git" {
            continue;
        }
        let mode = meta.mode();
        let sha1 = if meta.is_dir() {
            write_tree_object(&entry.path())?
        } else {
            write_blob_object(&entry.path(), true)?
        };
        tree.0.push(GitTreeEntry { name, mode, sha1 });
    }

    // Actually write the tree
    let root = find_git_root()?;

    let contents = tree.0.into_iter().fold(vec![], |mut v, e| {
        let mode = format!("{:o} {}", e.mode, e.name);
        v.extend(mode.bytes());
        v.push(0);
        let sha1 = hex::decode(e.sha1.0).unwrap();
        v.extend(sha1);
        v
    });

    let content_length = format!("{}", contents.len());
    let mut serialized = vec![b't', b'r', b'e', b'e', b' '];
    serialized.extend(content_length.bytes());
    serialized.push(0);
    serialized.extend(contents);

    let mut hasher = sha1::Sha1::new();
    hasher.update(&serialized);
    let hash = hasher.finalize();
    let hash = GitSha1(hex::encode(hash));

    let (sha_dir, sha_file_name) = hash.as_ref().split_at(2);
    let object_path = root
        .join(".git")
        .join("objects")
        .join(sha_dir)
        .join(sha_file_name);
    let compressed = zlib::compress(&serialized)?;
    fs::create_dir_all(object_path.parent().unwrap())?;
    fs::write(object_path, compressed)?;

    Ok(hash)
}

/// Writes the contents of the current working directory as a tree
fn write_tree(_args: &[String]) -> anyhow::Result<()> {
    let current_dir = std::env::current_dir()?;

    let sha1 = write_tree_object(&current_dir)?;
    println!("{}", sha1.0);

    Ok(())
}

/// Stores a blob into the object store and prints the hash of the object.
fn hash_object(args: &[String]) -> anyhow::Result<()> {
    let write_to_db = args.iter().find(|a| *a == "-w").is_some();

    let file_path: PathBuf = args
        .iter()
        .skip_while(|arg| arg.starts_with("-"))
        .next()
        .ok_or(anyhow!("hash-object requires argument \"<file>\""))
        .and_then(|s| Ok(PathBuf::from_str(&s)?))?;

    let root = find_git_root()?;

    let contents = std::fs::read(file_path).context("Unable to read source file for object")?;
    let content_length = format!("{}", contents.len());
    let mut serialized = vec![b'b', b'l', b'o', b'b', b' '];
    serialized.extend(content_length.bytes());
    serialized.push(0);
    serialized.extend(contents);

    let mut hasher = sha1::Sha1::new();
    hasher.update(&serialized);
    let hash = hasher.finalize();
    let hash = GitSha1(hex::encode(hash));
    println!("{hash:?}");

    if write_to_db {
        let (sha_dir, sha_file_name) = hash.as_ref().split_at(2);
        let object_path = root
            .join(".git")
            .join("objects")
            .join(sha_dir)
            .join(sha_file_name);
        let compressed = zlib::compress(&serialized)?;
        fs::create_dir_all(object_path.parent().unwrap())?;
        fs::write(object_path, compressed)?;
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
    } else if args[1] == "hash-object" {
        hash_object(&args[2..])?
    } else if args[1] == "ls-tree" {
        ls_tree(&args[2..])?
    } else if args[1] == "write-tree" {
        write_tree(&args[2..])?
    } else {
        println!("unknown command: {}", args[1])
    };
    Ok(())
}
