#[macro_use] extern crate scan_fmt;
use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::str;
use openssl::symm::{Cipher, Crypter, Mode};
use libc::strtoul;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::fs::OpenOptions;



static CIM_MAGIC_NUMBER: &'static [u8] = &[0x43, 0x49, 0x4d, 0xc1, 0x06, 0xad, 0xb0, 0x15];
static AES_DECRYPION_KEY: &'static [u8] = &[0xf8, 0xf0, 0x97, 0x9b, 0x4b, 0x9c, 0xf6, 0x16, 0xf0, 0x58, 0x3d, 0xe0, 0xe1, 0x93, 0x07, 0xd4];


fn convert_length(number: &str) -> u64 {
    let owned_number = CString::new(number.to_string()).unwrap();

    // I dont have a clue what is going on
    let size = unsafe {
        let base_8 = strtoul(owned_number.as_ptr(),ptr::null_mut(),8);
        return (!(base_8 & 0x1ff) >> 0x16 & 0x200) + (base_8 & 0xfffffe00);
    };
    
    return size
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

    *iv = block_buffer[len - 0x10..len].to_vec();
    return output
}


fn main() {
    let mut f = File::open("fw.cim").unwrap();

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
            return
            },
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
        i += 1;
        let output = read_and_decrypt(0x200, &mut f, &cipher, &mut iv);

        if &output[0x101..0x106] == b"ustar" {
            println!("ustar found");

            if let Ok(parsed_command) = str::from_utf8(&output[..12]){
                println!("Command: {}", parsed_command);
            }else{
                println!("Command RAW: {:?}", &output[0..12]);
            };

        }

        if &output[0..9] == b"signature" {
            println!("Signature block");

            //Read Signature Header Length in weird binary format
            let lengths: Vec<&str> = str::from_utf8(&output[0x7c..256]).unwrap().split("\u{0}").collect();
            let first_length = convert_length(lengths[0]);
            println!("Length: {}", first_length);
            
            //Read and Print Signature Header
            let output = read_and_decrypt(first_length as usize, &mut f, &cipher, &mut iv);
            let signatures = str::from_utf8(&output[..]).unwrap();

            println!("Image Header:");
            for line in signatures.split("\n") {
                if let Ok((a, b)) = scan_fmt!(line, "{} {}", String, String){
                    println!("  {}: {}", a, b);
                }
            }
            file.write_all(&output[..]);
        }else {
            //println!("Unknown block");
        }
    }
}

