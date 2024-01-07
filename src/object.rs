use anyhow::{anyhow, bail};

use crate::gitsha1::GitSha1;
use sha1::Digest;

#[derive(Debug, Clone)]
pub struct GitBlob(Vec<u8>);

impl GitBlob {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn content(&self) -> &[u8] {
        &self.0
    }

    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        // TODO: Make this parse the data on construction
        Ok(Self(data.to_vec()))
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Debug, Clone)]
pub struct GitTreeEntry {
    pub mode: u32,
    pub name: String,
    pub sha1: GitSha1,
}

#[derive(Debug, Clone)]
pub struct GitTree(Vec<GitTreeEntry>);

impl Default for GitTree {
    fn default() -> Self {
        Self(vec![])
    }
}

impl GitTree {
    pub fn new(entries: Vec<GitTreeEntry>) -> Self {
        Self(entries)
    }

    pub fn entries(&self) -> &[GitTreeEntry] {
        &self.0
    }

    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
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

        Ok(GitTree::new(entries))
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.entries().iter().fold(vec![], |mut v, e| {
            let mode = format!("{:o} {}", e.mode, e.name);
            v.extend(mode.bytes());
            v.push(0);
            let sha1 = hex::decode(e.sha1.as_ref()).unwrap();
            v.extend(sha1);
            v
        })
    }
}

// TODO: Make this parse the data on construction
#[derive(Debug, Clone)]
pub struct GitCommit(Vec<u8>);

impl GitCommit {
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        // TODO: Make this parse the data on construction
        Ok(Self(data.to_vec()))
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Debug, Clone)]
pub enum GitObject {
    Blob(GitBlob),
    Tree(GitTree),
    Commit(GitCommit),
}

impl GitObject {
    pub fn parse(data: &[u8]) -> anyhow::Result<GitObject> {
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
            "blob" => Ok(GitObject::Blob(GitBlob::parse(contents)?)),
            "tree" => Ok(GitObject::Tree(GitTree::parse(contents)?)),
            "commit" => Ok(GitObject::Commit(GitCommit::parse(contents)?)),
            t => Err(anyhow!("Invalid git object type found: {t}")),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let (mut result, content) = match self {
            Self::Blob(b) => (vec![b'b', b'l', b'o', b'b', b' '], b.serialize()),
            Self::Commit(c) => (
                vec![b'c', b'o', b'm', b'm', b'i', b't', b' '],
                c.serialize(),
            ),
            Self::Tree(t) => (vec![b't', b'r', b'e', b'e', b' '], t.serialize()),
        };

        let content_length = format!("{}", content.len());
        result.extend(content_length.bytes());
        result.push(0);
        result.extend(content.iter());
        result
    }

    pub fn hash(&self) -> GitSha1 {
        let serialized = self.serialize();
        let mut hasher = sha1::Sha1::new();
        hasher.update(&serialized);
        let hash = hasher.finalize();
        let hash: GitSha1 = hex::encode(hash)
            .try_into()
            .expect("Unable to convert hash into GitSha1");
        hash
    }
}
