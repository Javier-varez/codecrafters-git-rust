use anyhow::{anyhow, bail, Context};
use reqwest::StatusCode;
use reqwest::Url;
use sha1::Digest;

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

mod gitsha1;
mod object;
mod packfile;
mod zlib;

use gitsha1::GitSha1;
use object::GitBlob;
use object::GitObject;
use object::GitTree;
use object::GitTreeEntry;

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

trait MyIter: Iterator<Item = u8> + Clone {}

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
    GitObject::parse(&decompressed)
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
            print!("{}", std::str::from_utf8(blob.content())?);
        }
        GitObject::Tree(tree) => {
            for entry in tree.entries() {
                println!("{}", entry.name);
            }
        }
        GitObject::Commit(commit) => {
            unimplemented!()
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
                for entry in tree.entries() {
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
    let blob = GitObject::Blob(GitBlob::new(contents));
    let serialized = blob.serialize();

    let mut hasher = sha1::Sha1::new();
    hasher.update(&serialized);
    let hash = hasher.finalize();
    let hash: GitSha1 = hex::encode(hash).try_into()?;

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
    let mut tree = vec![];

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
        let (mode, sha1) = if meta.is_dir() {
            (0o040000, write_tree_object(&entry.path())?)
        } else {
            (
                meta.permissions().mode(),
                write_blob_object(&entry.path(), true)?,
            )
        };
        tree.push(GitTreeEntry { name, mode, sha1 });
    }
    tree.sort_by(|left, right| left.name.cmp(&right.name));
    let tree = GitObject::Tree(GitTree::new(tree));
    let serialized = tree.serialize();

    // Actually write the tree
    let root = find_git_root()?;

    let mut hasher = sha1::Sha1::new();
    hasher.update(&serialized);
    let hash = hasher.finalize();
    let hash: GitSha1 = hex::encode(hash).try_into()?;

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
    println!("{}", sha1.as_ref());

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
    let hash: GitSha1 = hex::encode(hash).try_into()?;
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

/// Creates a commit
fn commit_tree(args: &[String]) -> anyhow::Result<()> {
    if args.len() == 0 {
        bail!("Expected at least an argument for the tree hash");
    }

    let tree_hash: &str = &args[0];
    let tree_hash: GitSha1 = tree_hash.try_into()?;

    let parent = args.iter().skip_while(|a| *a != "-p").skip(1).next();
    let message = args
        .iter()
        .skip_while(|a| *a != "-m")
        .skip(1)
        .next()
        .ok_or(anyhow!("Expected a message for the commit"))?;

    let root = find_git_root()?;

    let time: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut contents = format!("tree {}\n", tree_hash.as_ref());
    if let Some(parent) = parent {
        contents.extend(format!("parent {}\n", parent).chars());
    }
    contents.extend(format!("author John Doe <john@doe> {time} +0000\n").chars());
    contents.extend(format!("committer John Doe <john@doe> {time} +0000\n").chars());
    contents.extend("\n".chars());
    contents.extend(message.chars());
    contents.extend("\n".chars());

    let content_length = format!("{}", contents.bytes().count());
    let mut serialized = vec![b'c', b'o', b'm', b'm', b'i', b't', b' '];
    serialized.extend(content_length.bytes());
    serialized.push(0);
    serialized.extend(contents.bytes());

    let mut hasher = sha1::Sha1::new();
    hasher.update(&serialized);
    let hash = hasher.finalize();
    let hash: GitSha1 = hex::encode(hash).try_into()?;

    let (sha_dir, sha_file_name) = hash.as_ref().split_at(2);
    let object_path = root
        .join(".git")
        .join("objects")
        .join(sha_dir)
        .join(sha_file_name);
    let compressed = zlib::compress(&serialized)?;
    fs::create_dir_all(object_path.parent().unwrap())?;
    fs::write(object_path, compressed)?;
    println!("{}", hash.as_ref());

    Ok(())
}

#[derive(Debug, Clone)]
enum PktLine {
    Flush,
    Delimiter,
    Data(Vec<u8>),
}

impl PktLine {
    fn pack_all(lines: &[PktLine]) -> Vec<u8> {
        let mut result = vec![];
        for e in lines {
            match e {
                PktLine::Flush => {
                    let len = 0u16;
                    let len = len.to_be_bytes();
                    let len = hex::encode(len);
                    result.extend(len.bytes());
                }
                PktLine::Delimiter => {
                    let len = 1u16;
                    let len = len.to_be_bytes();
                    let len = hex::encode(len);
                    result.extend(len.bytes());
                }
                PktLine::Data(data) => {
                    let len = data.len() as u16 + 5;
                    let len = len.to_be_bytes();
                    let len = hex::encode(len);
                    result.extend(len.bytes());
                    result.extend(data.iter());
                    result.push(b'\n');
                }
            }
        }
        result
    }

    fn unpack_all(content: &[u8]) -> anyhow::Result<Vec<PktLine>> {
        let mut offset = 0;
        let mut data = vec![];

        loop {
            let len: Vec<u8> = content.iter().skip(offset).take(4).cloned().collect();
            if len.len() == 0 {
                return Ok(data);
            } else if len.len() != 4 {
                bail!("Not enough lines to unpack packetline");
            }

            let len = hex::decode(len).context("Invalid pkt-line length")?;
            let len =
                u16::from_be_bytes(len.try_into().expect("Invalid packet length as str")) as usize;

            if len == 0 {
                data.push(PktLine::Flush);
                offset += 4;
            } else if len == 1 {
                data.push(PktLine::Delimiter);
                offset += 4;
            } else {
                let entry = PktLine::Data(
                    content
                        .iter()
                        .skip(offset + 4)
                        .cloned()
                        .take(len - 4)
                        .collect(),
                );
                data.push(entry);
                offset += len;
            }
        }
    }

    fn unpack_while_possible(content: &[u8]) -> anyhow::Result<(Vec<PktLine>, &[u8])> {
        let mut offset = 0;
        let mut data = vec![];

        loop {
            let len: Vec<u8> = content.iter().skip(offset).take(4).cloned().collect();
            if len.len() == 0 {
                return Ok((data, &[]));
            } else if len.len() != 4 {
                bail!("Not enough lines to unpack packetline");
            }

            let len = match hex::decode(len) {
                Ok(len) => len,
                Err(_) => {
                    // Assume this is no longer a pkt-line
                    return Ok((data, &content[offset..]));
                }
            };
            let len =
                u16::from_be_bytes(len.try_into().expect("Invalid packet length as str")) as usize;

            if len == 0 {
                data.push(PktLine::Flush);
                offset += 4;
            } else if len == 1 {
                data.push(PktLine::Delimiter);
                offset += 4;
            } else {
                let entry = PktLine::Data(
                    content
                        .iter()
                        .skip(offset + 4)
                        .cloned()
                        .take(len - 4)
                        .collect(),
                );
                data.push(entry);
                offset += len;
            }
        }
    }
}

#[derive(Debug, Clone)]
struct GitRef {
    sha1: GitSha1,
    name: String,
}

struct GitClient {
    repo_url: Url,
    path: PathBuf,
}

impl GitClient {
    fn new(repo_url: Url, path: PathBuf) -> Self {
        Self { repo_url, path }
    }

    fn discover_refs(&self) -> anyhow::Result<Vec<GitRef>> {
        let url = self.repo_url.join("info/refs")?;
        let response = reqwest::blocking::Client::builder()
            .build()?
            .get(url)
            .query(&[("service", "git-upload-pack")])
            .send()?;

        if response.status() != StatusCode::OK {
            bail!(
                "Server replied with unexpected status code: {}",
                response.status()
            );
        }

        let is_smart_server = response
            .headers()
            .get("content-type")
            .is_some_and(|v| v == "application/x-git-upload-pack-advertisement");
        if !is_smart_server {
            bail!("Only smart git servers are supported");
        }

        let bytes = response.bytes()?;
        let pkt_lines = PktLine::unpack_all(&bytes)?;

        let refs = pkt_lines
            .iter()
            .skip_while(|e| !matches!(e, PktLine::Flush))
            .skip(1)
            .take_while(|e| !matches!(e, PktLine::Flush))
            .map(|e| -> anyhow::Result<GitRef> {
                match e {
                    PktLine::Data(data) => {
                        let sha1: GitSha1 = std::str::from_utf8(
                            &data.iter().take(40).cloned().collect::<Vec<u8>>(),
                        )?
                        .try_into()?;
                        let end = data
                            .iter()
                            .enumerate()
                            .skip(41)
                            .find(|(_i, v)| **v == 0 || **v == b'\n')
                            .map(|(i, _)| i)
                            .ok_or(anyhow!("Expected end of line in marker"))?;
                        let name = std::str::from_utf8(&data[41..end])?.to_string();
                        Ok(GitRef { sha1, name })
                    }
                    PktLine::Delimiter => {
                        panic!("Unexpected marker!");
                    }
                    PktLine::Flush => {
                        panic!("Unexpected marker!");
                    }
                }
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(refs)
    }

    pub fn get_ref(&self, r: &GitRef) -> anyhow::Result<()> {
        let url = self.repo_url.join("git-upload-pack")?;
        let lines = [
            PktLine::Data("command=fetch".to_string().into_bytes()),
            PktLine::Data("object-format=sha1".to_string().into_bytes()),
            PktLine::Delimiter,
            PktLine::Data("thin-pack".to_string().into_bytes()),
            PktLine::Data("ofs-delta".to_string().into_bytes()),
            PktLine::Data(format!("want {}", r.sha1.as_ref()).into_bytes()),
            PktLine::Data("done".to_string().into_bytes()),
            PktLine::Flush,
        ];
        let body = PktLine::pack_all(&lines);
        println!("body: {}", std::str::from_utf8(&body)?);
        let response = reqwest::blocking::Client::builder()
            .build()?
            .post(url)
            .header("Content-Type", "application/x-git-upload-pack-request")
            .header("Accept", "application/x-git-upload-pack-result")
            .header("git-protocol", "version=2")
            .body(body)
            .send()?;

        if response.status() != StatusCode::OK {
            bail!(
                "Server replied with unexpected status code: {}",
                response.status()
            );
        }

        let bytes = response.bytes()?;
        let packs = PktLine::unpack_all(&bytes)?;

        const PACK_MARKER: u8 = 1;
        const MSG_MARKER: u8 = 2;
        let mut packfile: Vec<u8> = vec![];
        for pack in packs {
            match pack {
                PktLine::Data(d) => {
                    if d.iter().next().is_some_and(|val| *val == PACK_MARKER) {
                        packfile.extend(d.iter().skip(1));
                    } else if d.iter().next().is_some_and(|val| *val == MSG_MARKER) {
                        let msg = String::from_utf8_lossy(&d[1..]);
                        println!("{msg}");
                    }
                }
                PktLine::Flush | PktLine::Delimiter => {}
            }
        }

        // let curdir = current_dir()?;
        // std::fs::write(curdir.join("packfile.pack"), &packfile)?;
        let packfile = packfile::parse(&packfile)?;

        Ok(())
    }
}

fn clone(args: &[String]) -> anyhow::Result<()> {
    if args.len() < 2 {
        bail!("not enough arguments");
    }

    let mut url = args[0].clone();
    if !url.ends_with("/") {
        url.push('/');
    }
    let url = Url::parse(&url)?;
    let path = PathBuf::from_str(&args[1])?;
    let client = GitClient::new(url, path);

    let refs = client.discover_refs()?;
    let head = refs.iter().find(|r| r.name == "HEAD").unwrap();
    client.get_ref(head)?;

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
    } else if args[1] == "commit-tree" {
        commit_tree(&args[2..])?
    } else if args[1] == "clone" {
        clone(&args[2..])?
    } else {
        println!("unknown command: {}", args[1])
    };
    Ok(())
}
