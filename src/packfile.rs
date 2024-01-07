use std::collections::HashMap;

use anyhow::{anyhow, bail};

use crate::gitsha1::GitSha1;
use crate::object::{GitBlob, GitCommit, GitObject, GitTree};
use crate::zlib;

#[derive(Debug, Clone)]
struct Header {
    version: u32,
    num_objs: u32,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub objects: HashMap<usize, GitObject>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
enum PackType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl TryFrom<u8> for PackType {
    type Error = anyhow::Error;
    fn try_from(source: u8) -> anyhow::Result<Self> {
        match source {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Tag),
            6 => Ok(Self::OfsDelta),
            7 => Ok(Self::RefDelta),
            _ => Err(anyhow!("Invalid pack type: {source}")),
        }
    }
}

fn decode_variable_length_int(data: &[u8]) -> anyhow::Result<(PackType, usize, usize)> {
    const MASK: u8 = 0x7f;
    const TYPE_MASK: u8 = 0x70;
    const TYPE_OFF: u8 = 4;
    const FIRST_MASK: u8 = 0x0f;
    const CONT_BIT: u8 = 0x80;

    let mut result = 0usize;
    let mut ty = None;
    let mut consumed = 0;
    let mut shift = 0;

    let mut finished = false;

    for byte in data {
        if ty.is_none() {
            ty = Some(((byte & TYPE_MASK) >> TYPE_OFF).try_into()?);
            result = (byte & FIRST_MASK) as usize;
            shift += 4;
        } else {
            result = result | ((byte & MASK) as usize) << shift;
            shift += 7;
        }
        consumed += 1;

        if byte & CONT_BIT == 0 {
            finished = true;
            break;
        }
    }
    if !finished {
        bail!("Ran out of data while parsing variable length integer for type and size");
    }
    Ok((ty.unwrap(), result, consumed))
}

fn construct_git_object_from_raw_data(
    pack_type: PackType,
    data: &[u8],
) -> anyhow::Result<GitObject> {
    match pack_type {
        PackType::Blob => Ok(GitObject::Blob(GitBlob::parse(&data)?)),
        PackType::Tree => Ok(GitObject::Tree(GitTree::parse(&data)?)),
        PackType::Commit => Ok(GitObject::Commit(GitCommit::parse(&data)?)),
        PackType::Tag => {
            unimplemented!()
        }
        PackType::OfsDelta | PackType::RefDelta => {
            bail!("Cannot construct git object from ref");
        }
    }
}

fn leb64(data: &[u8]) -> anyhow::Result<(usize, usize)> {
    const MASK: u8 = 0x7f;
    const CONT_BIT: u8 = 0x80;
    const SHIFT: usize = 7;

    let mut result = 0usize;
    let mut consumed = 0;

    let mut finished = false;

    for byte in data {
        if consumed > 0 {
            // TODO: I'm not sure where this comes from...
            result += 1;
        }
        result = result << SHIFT | (byte & MASK) as usize;

        consumed += 1;

        if byte & CONT_BIT == 0 {
            finished = true;
            break;
        }
    }
    if !finished {
        bail!("Ran out of data while parsing variable length integer for type and size");
    }
    Ok((result, consumed))
}

pub fn parse(data: &[u8]) -> anyhow::Result<PackFile> {
    const HEADER_SIZE: usize = 12;
    // Check signature
    if data.len() < HEADER_SIZE {
        bail!("pack file is too short");
    }

    if data[..4] != [b'P', b'A', b'C', b'K'] {
        bail!("Invalid signature");
    }

    let version = u32::from_be_bytes(data[4..8].try_into()?);
    let num_objs = u32::from_be_bytes(data[8..12].try_into()?);
    let header = Header { version, num_objs };
    dbg!(&header);

    let mut objects = HashMap::new();
    let mut offset = HEADER_SIZE;

    for _ in 0..num_objs {
        if offset >= data.len() {
            bail!("Pack seems to be incomplete or malformated!");
        }

        let obj_offset = offset;
        let (ty, decompressed_size, consumed) = decode_variable_length_int(&data[offset..])?;

        offset += consumed;
        if offset >= data.len() {
            bail!("Pack seems to be incomplete or malformated!");
        }

        match ty {
            PackType::Blob | PackType::Commit | PackType::Tree | PackType::Tag => {
                let (obj_data, compressed_size) =
                    zlib::decompress_with_consumed_input(&data[offset..])?;
                offset += compressed_size;

                let object = construct_git_object_from_raw_data(ty, &obj_data)?;
                let hash = object.hash();

                println!("hash: {hash:?}, type: {ty:?}, decompressed_size {decompressed_size}");
                objects.insert(obj_offset, object);

                if obj_data.len() != decompressed_size {
                    bail!("Decompressed size for object is not correct!");
                }
            }
            PackType::OfsDelta => {
                let (base_offset, consumed) = leb64(&data[offset..])?;
                offset += consumed;

                println!("Base offset: {base_offset}, consumed: {consumed}");
                println!("Original obj {}", obj_offset - base_offset);
                if let Some(obj) = objects.get(&(obj_offset - base_offset)) {
                    let hash = obj.hash();
                    println!("Original obj {hash:?}");
                } else {
                    println!("Unknwnon offset...");
                }

                unimplemented!()
            }
            PackType::RefDelta => {
                bail!("Unexpected compressed data in ref-delta format");
            }
        }
    }

    bail!("REMOVE ME");

    Ok(PackFile { objects })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode variable int numbers.
    #[inline]
    pub fn otherLeb64(d: &[u8]) -> (u64, usize) {
        let mut i = 0;
        let mut c = d[i];
        i += 1;
        let mut value = c as u64 & 0x7f;
        while c & 0x80 != 0 {
            c = d[i];
            i += 1;
            debug_assert!(i <= 10, "Would overflow value at 11th iteration");
            value += 1;
            value = (value << 7) + (c as u64 & 0x7f)
        }
        (value, i)
    }

    #[test]
    fn test_leb64() {
        let input = [0xe5, 0x8e, 0x26];
        assert_eq!(leb64(&input).unwrap().0 as u64, otherLeb64(&input).0);
    }

    #[test]
    fn test_parse() {
        let file = std::fs::read("/home/javier/code/test/configs/.git/objects/pack/pack-d0fce997b9676a0ef4e7b46c48aa0d74383251f6.pack").unwrap();
        parse(&file).unwrap();
    }
}
