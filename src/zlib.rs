use anyhow::bail;
use flate2::Status;

pub fn decompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (res, _) = decompress_with_consumed_input(data)?;
    Ok(res)
}

pub fn compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut compressor = flate2::Compress::new(flate2::Compression::fast(), true);
    let mut compressed = vec![];

    loop {
        let in_offset = compressor.total_in() as usize;

        const BLOCK_SIZE: usize = 0x4000;
        compressed.reserve_exact(BLOCK_SIZE);

        if in_offset == data.len() {
            let status = compressor.compress_vec(
                &data[in_offset..],
                &mut compressed,
                flate2::FlushCompress::Finish,
            )?;
            assert_eq!(status, Status::StreamEnd);
            break;
        }

        let status = compressor.compress_vec(
            &data[in_offset..],
            &mut compressed,
            flate2::FlushCompress::Sync,
        )?;

        if status == Status::BufError {
            bail!("zlib compression error");
        }
    }

    Ok(compressed)
}

pub fn decompress_with_consumed_input(data: &[u8]) -> anyhow::Result<(Vec<u8>, usize)> {
    let mut dec = flate2::Decompress::new(true);
    let mut decompressed = vec![];

    loop {
        let in_offset = dec.total_in() as usize;

        const BLOCK_SIZE: usize = 128;
        decompressed.reserve_exact(BLOCK_SIZE);

        let status = dec.decompress_vec(
            &data[in_offset..],
            &mut decompressed,
            flate2::FlushDecompress::Sync,
        )?;

        if status == Status::StreamEnd {
            break;
        } else if status == Status::BufError {
            bail!("zlib decompression error");
        }
    }

    Ok((decompressed, dec.total_in() as usize))
}
