#[macro_use]
extern crate scan_fmt;
extern crate clap;

use std::fs::File;
use std::io::prelude::*;
use std::str;

use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

use libc::strtoul;

use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::PathBuf;
use std::ptr;

use clap::{App, Arg, SubCommand};

static CIM_MAGIC_NUMBER: &'static [u8] = &[0x43, 0x49, 0x4d, 0xc1, 0x06, 0xad, 0xb0, 0x15];
static AES_DECRYPION_KEY: &'static [u8] = &[
    0xf8, 0xf0, 0x97, 0x9b, 0x4b, 0x9c, 0xf6, 0x16, 0xf0, 0x58, 0x3d, 0xe0, 0xe1, 0x93, 0x07, 0xd4,
];
static HMAC_KEY: &'static [u8] = &[
    0x2b, 0x7f, 0x0c, 0x21, 0x55, 0xda, 0x03, 0xd9, 0xe3, 0xa5, 0xb3, 0xe8, 0x8f, 0x34, 0xaf, 0x32,
];
static SH_CHALLENGE_RESPONSE: &'static [u8] = &[0xa7, 0x25, 0x57, 0xd1, 0x90, 0x0e, 0x3d, 0x6b];

fn convert_length(number: &str) -> u64 {
    let owned_number = CString::new(number.to_string()).unwrap();

    // I dont have a clue what is going on
    let size = unsafe {
        let base_8 = strtoul(owned_number.as_ptr(), ptr::null_mut(), 8);
        (!(base_8 & 0x1ff) >> 0x16 & 0x200) + (base_8 & 0xfffffe00)
    };

    return size;
}

fn read_and_decrypt(len: usize, f: &mut File, cipher: &Cipher, mut iv: &mut Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &AES_DECRYPION_KEY, Some(&iv)).unwrap();

    let mut block_buffer = vec![0 as u8; len];
    let read_bytes = f.read(&mut block_buffer).unwrap();
    if read_bytes == 0 {
        panic!("EOF");
    }
    let mut output = vec![0 as u8; block_buffer.len() + Cipher::aes_128_cbc().block_size()];
    let decrypted_result = crypter.update(&block_buffer, &mut output);

    //let mut file = OpenOptions::new().append(true).open("raw.img").unwrap();
    //file.write_all(&output[..]);

    *iv = block_buffer[len - 0x10..len].to_vec();
    return output;
}

fn dump_firmware(source: &str, target: &str) {
    let mut f = File::open(source).unwrap();

    let target_path = PathBuf::from(target);

    let mut header_buffer = [0; 12];

    f.read(&mut header_buffer).unwrap();

    if &header_buffer[..8] != CIM_MAGIC_NUMBER {
        println!("Invalid CIM File: Magic number does not match");
        return;
    }

    match &header_buffer[8..10] {
        [0, 0] => println!("Encrypted using AES"),
        [0, 1] => {
            println!("Encrypted using RC4, not yet supported");
            return;
        }
        _ => {
            println!("Unknown Encryption");
            return;
        }
    };

    println!("AES KEY LENGHT: {:?}", &AES_DECRYPION_KEY.len());
    println!("AES KEY Number Offset: {:?}", &header_buffer[10..12]);

    let mut iv = vec![0; 16];
    f.read(&mut iv).unwrap();
    println!("IV: {:?}", &iv);

    let cipher = Cipher::aes_128_cbc();
    let mut i = 0;

    loop {
        println!("------------------------------------");
        i += 1;
        let output = read_and_decrypt(0x200, &mut f, &cipher, &mut iv);

        if &output[0x101..0x106] != b"ustar" {
            panic!("ustar not found");
        }

        if let Ok(parsed_command) = str::from_utf8(&output[..12]) {
            println!("Command: {}", parsed_command);
        } else {
            panic!("Command RAW: {:?}", &output[0..12]);
        };

        //Read Signature Header Length in weird binary format
        let lengths: Vec<&str> = str::from_utf8(&output[0x7c..256])
            .unwrap()
            .split("\u{0}")
            .collect();
        let first_length = convert_length(lengths[0]);
        println!("Block Length: {}", first_length);
        let second_length = convert_length(lengths[1]);
        println!("Second Length: {}", second_length);
        let third_length = convert_length(lengths[2]);
        println!("third_length Length: {}", third_length);

        if &output[0..9] == b"signature" {
            println!("Signature block");
            //Read and Print Signature Header
            let output = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            let signatures = str::from_utf8(&output[..]).unwrap();

            println!("Image Header:");
            for line in signatures.split("\n") {
                if let Ok((a, b)) = scan_fmt!(line, "{} {}", String, String) {
                    println!("  {}: {}", a, b);
                }
            }
        } else if &output[0..10] == b"_kernel-0b" {
            println!("Kernel 0b Block");

            let mut file = File::create(target_path.join("kernel_0b.uImage")).unwrap();
            let file_content = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            file.write_all(&file_content);
        } else if &output[0..10] == b"_kernel-12" {
            println!("Kernel 12 Block");

            let mut file = File::create(target_path.join("kernel_12.uImage")).unwrap();
            let file_content = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            file.write_all(&file_content);
        } else if &output[0..5] == b"_mtd1" {
            println!("MTD1 Block");

            let mut file = File::create(target_path.join("mtd1.uImage")).unwrap();
            let file_content = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            file.write_all(&file_content);
        } else if &output[0..5] == b"_mtd2" {
            println!("MTD2 Block");

            let mut file = File::create(target_path.join("mtd2.sqfs.gz")).unwrap();
            let file_content = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            file.write_all(&file_content);
        } else if &output[0..5] == b"_mtd5" {
            println!("MTD5 Block");

            let mut file = File::create(target_path.join("mtd5.sqfs.gz")).unwrap();
            let file_content = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            file.write_all(&file_content);
        } else if &output[0..7] == b"execute" {
            println!("Execute Block");

            let mut file = File::create(target_path.join("execute.sh")).unwrap();
            let file_content = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);

            let key = PKey::hmac(HMAC_KEY).unwrap();

            // Compute the HMAC
            let mut signer = Signer::new(MessageDigest::sha1(), &key).unwrap();
            signer.update(&file_content[..2524]).unwrap();
            let hmac = signer.sign_to_vec().unwrap();
            println!("HMAC: {:x?}", hmac);

            file.write_all(&file_content);
        } else if &output[0..5] == b"file0" {
            println!("File Block");

            let mut file = File::create(target_path.join("file.tar.gz")).unwrap();
            let file_content = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            file.write_all(&file_content);
        }
    }
}

fn calculate_response() {
    let challenge = loop {
        print!("Please enter the given challenge: ");
        io::stdout().flush().expect("flush failed");
        let stdin = io::stdin();
        let mut iterator = stdin.lock().lines();
        let input = iterator
            .next()
            .expect("No user input could been read")
            .expect("No user input found");
        if input.len() != 6 {
            println!("A challenge needs to be 6 chars long");
        } else {
            break input;
        }
    };

    let mut data = vec![];
    data.extend_from_slice(&challenge.as_bytes()[..3]);
    data.extend_from_slice(SH_CHALLENGE_RESPONSE);
    data.extend_from_slice(&challenge.as_bytes()[3..]);

    let res = hash(MessageDigest::sha1(), &data).unwrap();

    println!("Correct response is: {:05}", res[3] as u16 * res[13] as u16);
}

fn main() {
    let matches = App::new("hp-cim-tools")
        .version("0.1")
        .author("Bela Stoyan <cim@be7a.de>")
        .about("Various utils to work with HP MSM4XX Firmware")
        .subcommand(
            SubCommand::with_name("dump")
                .about("Dumps a firmware image")
                .version("0.1")
                .arg(
                    Arg::with_name("source")
                        .short("f")
                        .help("Location of the firmware image")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("dest")
                        .short("d")
                        .help("Destination FOLDER of the extracted files")
                        .index(2),
                ),
        )
        .subcommand(
            SubCommand::with_name("sh")
                .about("Calculates the response to the enable sh challenge")
                .version("0.1"),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("sh") {
        calculate_response();
    } else if let Some(matches) = matches.subcommand_matches("dump") {
        let dest_path = match matches.value_of("dest") {
            Some(dest) => {
                fs::create_dir(dest);
                dest
            }
            None => {
                fs::create_dir("extracted");
                "extracted"
            }
        };
        dump_firmware(matches.value_of("source").unwrap(), dest_path);
    }
}