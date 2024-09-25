use std::fs::File;
use std::io::{self, BufRead};
//use std::io;
use std::io::Read;
use std::env;
use std::str;
use std::collections::HashMap;

use flate2::read::ZlibDecoder;
use clap::Parser;

mod pack2;

fn read_le_u32(data: &Vec<u8>, offset: usize) -> u32 {
    return u32::from_le_bytes(data[offset..offset+4].try_into().expect("failed?"));
}

fn read_be_u32(data: &Vec<u8>, offset: usize) -> u32 {
    return u32::from_be_bytes(data[offset..offset+4].try_into().expect("failed?"));
}

fn read_le_u64(data: &Vec<u8>, offset: usize) -> u64 {
    return u64::from_le_bytes(data[offset..offset+8].try_into().expect("failed?"));
}

struct Pack2Asset {
    file_hash: u64,
    name: String,
    offset: u64,
    length: u64,
    flags: u32,
    data_hash: u32,
    data: Vec<u8>
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {

    /// action to do: dump|print
    #[arg(short, long)]
    action: String,

}

fn main() -> std::io::Result<()> {

    let args = Args::parse();

    println!("working dir: {}", env::current_dir()?.display());

    let hashes: HashMap<u64, String> = read_namelist().expect("failed to read namelist");

    let output: Vec<Pack2Asset> = read_file("data_x64_0.pack2", &hashes)?;

    if args.action == "dump" {
        std::fs::create_dir_all("./data_x64_0/")?;

        for ele in output {
            let _ = std::fs::write(format!("./data_x64_0/{}", ele.name), ele.data);
        }
    } else if args.action == "info" {
        for asset in output {
            println!("file_hash: {:#08x}, offset: {:#08x}, length: {:#08x}, flags: {:#08x}, data_hash: {:#08x}, name: {}",
                asset.file_hash, asset.offset, asset.length, asset.flags, asset.data_hash, asset.name);
        }
    } else {
        eprintln!("invalid action! expected dump|info");
    }

    return Ok(());
}

fn read_namelist() -> Result<HashMap<u64, String>, std::io::Error> {

    let file: File = File::open("namelist.txt")?;

    let mut hashes: HashMap<u64, String> = HashMap::new();

    let lines: io::Lines<io::BufReader<File>> = io::BufReader::new(file).lines();
    for line in lines.flatten() {
        let crc: u64 = pack2::crc64(line.to_uppercase().as_bytes());
        //println!("hash {:#x} -> {}", crc, line.clone());
        hashes.insert(crc, line);
    }

    println!("read {} hashes from namelist", hashes.len());

    return Ok(hashes);
}

fn read_file(file_name: &str, hashes: &HashMap<u64, String>) -> Result<Vec<Pack2Asset>, std::io::Error> {

    println!("{}> opening", file_name);

    let mut file: File = File::open(file_name)?;

    let mut data: Vec<u8> = vec![];
    _ = file.read_to_end(&mut data);

    let magic: u32 = read_le_u32(&data, 0);
    let asset_count: u32 = read_le_u32(&data, 4);
    let file_size: u64 = read_le_u64(&data, 8);
    let map_offset: u64 = read_le_u64(&data, 16);

    println!("{}> magic: {}, asset_count: {}, file_size: {}, map_offset: {}", file_name, magic, asset_count, file_size, map_offset);

    let mut map_index: usize = map_offset as usize;

    let mut assets: Vec<Pack2Asset> = vec![];
    while map_index < file_size as usize {

        let file_hash: u64 = read_le_u64(&data, map_index + 0);
        let offset: usize = read_le_u64(&data, map_index + 8) as usize;
        let mut length: usize = read_le_u64(&data, map_index + 16) as usize;
        let flags: u32 = read_le_u32(&data, map_index + 24);
        let data_hash: u32 = read_le_u32(&data, map_index + 28);

        map_index += 32;

        // lowest bit indicates compressed using zlib or not
        let is_zipped: bool = (flags & 0x01 == 0x01) && length > 0;

        let asset_data: Vec<u8>;
        if is_zipped {
            let zip_header: u32 = read_le_u32(&data, offset);
            if zip_header != 0xd4c3b2a1 {
                println!("ERR {}> expected asset at offset {:#x} to have a zip header of 0xd4c3b2a1, had {:#x} instead!", file_name, offset, zip_header);
                continue;
            }

            //println!("{}> zip header: {:#x}, zipped length: {:#x}", file_name, zip_header, zipped_length);

            // first, read |length| bytes and decompress those
            let mut d: ZlibDecoder<&[u8]> = ZlibDecoder::new(&data[offset + 8 .. offset + length]);
            // next, the length of the decompressed data and the length read from the pack2 must match
            length = read_be_u32(&data, offset + 4) as usize;

            let mut zlip_data = vec![];
            let _ = d.read_to_end(&mut zlip_data);
            asset_data = zlip_data.clone();

            if asset_data.len() != length {
                println!("ERR {}> at offset {:#x}, expected to read {} bytes, read {} instead!", file_name, offset, length, asset_data.len());
            }

        } else {
            asset_data = data[offset..offset + length].to_vec();
        }

        let name: String;
        if hashes.contains_key(&file_hash) {
            name = hashes.get(&file_hash).unwrap().clone();
        } else {
            //println!("failed to find hash {}", file_hash);
            name = format!("{:#x}.bin", file_hash);
        }

        let asset: Pack2Asset = Pack2Asset {
            name: name,
            file_hash: file_hash,
            offset: offset as u64,
            length: length as u64,
            flags: flags,
            data_hash: data_hash,
            data: asset_data
        };

        if asset.data.len() != length {
            println!("ERR {}> data length of {} does not match expected {}", file_name, asset.data.len(), length);
        }

        assets.push(asset);
    }

    println!("{}> read {}/{} assets", file_name, assets.len(), asset_count);

    return Ok(assets);
}
