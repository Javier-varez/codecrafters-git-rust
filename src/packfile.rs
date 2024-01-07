use std::collections::HashMap;

use anyhow::{anyhow, bail};

use crate::object::{GitBlob, GitCommit, GitObject, GitTree};
use crate::zlib;

#[derive(Debug, Clone)]
struct Header {
    version: u32,
    num_objs: u32,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub objects: Vec<GitObject>,
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

fn decode_type_and_length(data: &[u8]) -> anyhow::Result<(PackType, usize, usize)> {
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

fn decode_variable_length_int(data: &[u8]) -> anyhow::Result<(usize, usize)> {
    const MASK: u8 = 0x7f;
    const CONT_BIT: u8 = 0x80;

    let mut result = 0usize;
    let mut consumed = 0;
    let mut shift = 0;

    let mut finished = false;

    for byte in data {
        result = result | ((byte & MASK) as usize) << shift;
        shift += 7;
        consumed += 1;

        if byte & CONT_BIT == 0 {
            finished = true;
            break;
        }
    }
    if !finished {
        bail!("Ran out of data while parsing variable length integer");
    }
    Ok((result, consumed))
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
            // Because the fact that there is another byte it means it cannot be 0,
            // this encodes a bit more data (1-128)
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

#[derive(Debug, Clone)]
enum DeltaInst {
    CopyBlob { offset: usize, size: usize },
    AddData { data: Vec<u8> },
}

struct DeltaInstIter<'a> {
    data: &'a [u8],
    current_offset: usize,
}

impl<'a> DeltaInstIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            current_offset: 0,
        }
    }
}

impl<'a> std::iter::Iterator for DeltaInstIter<'a> {
    type Item = DeltaInst;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset >= self.data.len() {
            return None;
        }

        const DIFF_MASK: u8 = 0x80;
        const COPY_INST: u8 = 0x80;
        let mut offset = self.current_offset;

        let inst = self.data[offset];
        if (inst & DIFF_MASK) == COPY_INST {
            offset += 1;

            let mut chunk_offset = 0usize;
            for i in 0..4 {
                let bit = 1u8 << i;
                if inst & bit == bit {
                    assert!(self.data.len() > offset);
                    let part = self.data[offset] as usize;
                    chunk_offset |= part << (8 * i);
                    offset += 1;
                }
            }

            let mut size = 0;
            for i in 4..7 {
                let bit = 1u8 << i;
                if inst & bit == bit {
                    assert!(self.data.len() > offset);
                    let chunk = self.data[offset] as usize;
                    size |= chunk << (8 * (i - 4));
                    offset += 1;
                }
            }

            self.current_offset = offset;
            Some(DeltaInst::CopyBlob {
                offset: chunk_offset,
                size,
            })
        } else {
            offset += 1;
            let len = inst as usize;

            let data: Vec<u8> = self.data.iter().cloned().skip(offset).take(len).collect();
            assert_eq!(data.len(), len);
            offset += len;

            self.current_offset = offset;
            Some(DeltaInst::AddData { data })
        }
    }
}

fn parse_ofs_delta_object(obj_data: &[u8], base_obj_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut offset = 0;
    let (base_obj_size, consumed) = decode_variable_length_int(&obj_data[offset..])?;
    offset += consumed;
    let (obj_size, consumed) = decode_variable_length_int(&obj_data[offset..])?;
    offset += consumed;

    if base_obj_size != base_obj_data.len() {
        bail!(
            "Stored base object size and actual base object size do not match: {} vs {}",
            base_obj_data.len(),
            base_obj_size
        );
    }

    let mut result = vec![];
    for inst in DeltaInstIter::new(&obj_data[offset..]) {
        match inst {
            DeltaInst::AddData { data } => {
                result.extend(data);
            }
            DeltaInst::CopyBlob { offset, size } => {
                result.extend(base_obj_data[offset..offset + size].iter());
            }
        }
    }

    if result.len() != obj_size {
        bail!("Did not obtain the correct object size after following the instructions");
    }
    Ok(result)
}

fn parse_header(data: &[u8]) -> anyhow::Result<(Header, &[u8])> {
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
    Ok((Header { version, num_objs }, &data[HEADER_SIZE..]))
}

pub fn parse(data: &[u8]) -> anyhow::Result<PackFile> {
    let (header, data) = parse_header(data)?;

    if header.version != 2 {
        bail!("Unsupported packfile version: {}", header.version);
    }

    let mut object_map = HashMap::new();
    let mut objects = vec![];
    let mut offset = 0;

    for _ in 0..header.num_objs {
        if offset >= data.len() {
            bail!("Pack seems to be incomplete or malformated!");
        }

        let obj_offset = offset;
        let (ty, decompressed_size, consumed) = decode_type_and_length(&data[offset..])?;

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

                if obj_data.len() != decompressed_size {
                    bail!("Decompressed size for object is not correct!");
                }

                object_map.insert(obj_offset, (hash, obj_data, ty));
                objects.push(object);
            }
            PackType::OfsDelta => {
                let (base_offset, consumed) = leb64(&data[offset..])?;
                offset += consumed;

                let Some((_base_obj_hash, base_obj_data, base_obj_type)) =
                    object_map.get(&(obj_offset - base_offset))
                else {
                    bail!("Unknown base object at offset {base_offset}");
                };

                let (obj_data, compressed_size) =
                    zlib::decompress_with_consumed_input(&data[offset..])?;
                offset += compressed_size;

                if obj_data.len() != decompressed_size {
                    bail!("Decompressed size for object is not correct!");
                }

                let obj_data = parse_ofs_delta_object(&obj_data, base_obj_data)?;

                let object = construct_git_object_from_raw_data(*base_obj_type, &obj_data)?;
                let hash = object.hash();

                object_map.insert(obj_offset, (hash, obj_data, *base_obj_type));
                objects.push(object);
            }
            PackType::RefDelta => {
                bail!("Unexpected compressed data in ref-delta format");
            }
        }
    }

    Ok(PackFile { objects })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let file = std::fs::read("/home/javier/code/test/configs/.git/objects/pack/pack-d0fce997b9676a0ef4e7b46c48aa0d74383251f6.pack").unwrap();
        parse(&file).unwrap();
    }
}
