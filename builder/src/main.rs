
use std::path::Path;
use std::fs::OpenOptions;
use std::fs;
use std::env;
use std::io::prelude::*;
use rand_core::RngCore;
use log::debug;
use eccfs_builder::{ro, rw};
use eccfs::*;


fn build_ro(mode: String, target: String) {
    debug!("Building ROFS {}", target);

    let from = format!("test/{}", &target);
    let to_dir = "test";
    let image = format!("{}.roimage", &target);
    let work_dir = "test";

    let k = match mode.as_str() {
        "enc" => {
            let mut k = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut k);
            Some(k)
        }
        "int" => {
            None
        }
        _ => panic!("unrecognized fsmode"),
    };

    let mode = ro::build_from_dir(
        Path::new(&from),
        Path::new(&to_dir),
        Path::new(&image),
        Path::new(work_dir),
        k,
    ).unwrap();
    match &mode {
        FSMode::IntegrityOnly(hash) => {
            let s = hex::encode_upper(hash);
            println!("Built in IntegrityOnly Mode:");
            println!("Hash: {}", s);
        }
        FSMode::Encrypted(key, mac) => {
            assert_eq!(k.unwrap(), *key);
            println!("Built in Encrypted Mode:");
            let k = hex::encode_upper(key);
            let m = hex::encode_upper(mac);
            println!("Key: {}", k);
            println!("Mac: {}", m);
        }
    }
    // save mode to file
    let name = format!("test/{}.mode", target);
    let _ = fs::remove_file(name.clone());
    let mut f = OpenOptions::new().write(true).create_new(true).open(name).unwrap();
    let written = f.write(unsafe {
        std::slice::from_raw_parts(
            &mode as *const FSMode as *const u8,
            std::mem::size_of::<FSMode>(),
        )
    }).unwrap();
    assert_eq!(written, std::mem::size_of::<FSMode>());
}

fn build_rw(mode: String, target: String) {
    debug!("Building RWFS {}", target);

    let from = format!("test/{}", &target);
    let to = format!("test/{}.rwimage", &target);

    let k = match mode.as_str() {
        "enc" => {
            let mut k = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut k);
            Some(k)
        }
        "int" => {
            None
        }
        _ => panic!("unrecognized fsmode"),
    };

    let mode = rw::build_from_dir(
        Path::new(&from),
        Path::new(&to),
        k,
    ).unwrap();
    match &mode {
        FSMode::IntegrityOnly(hash) => {
            let s = hex::encode_upper(hash);
            println!("Built in IntegrityOnly Mode:");
            println!("Hash: {}", s);
        }
        FSMode::Encrypted(key, mac) => {
            assert_eq!(k.unwrap(), *key);
            println!("Built in Encrypted Mode:");
            let k = hex::encode_upper(key);
            let m = hex::encode_upper(mac);
            println!("Key: {}", k);
            println!("Mac: {}", m);
        }
    }
    // save mode to file
    let name = format!("test/{}.mode", target);
    let _ = fs::remove_file(name.clone());
    let mut f = OpenOptions::new().write(true).create_new(true).open(name).unwrap();
    let written = f.write(unsafe {
        std::slice::from_raw_parts(
            &mode as *const FSMode as *const u8,
            std::mem::size_of::<FSMode>(),
        )
    }).unwrap();
    assert_eq!(written, std::mem::size_of::<FSMode>());
}

fn build_empty(mode: String, target: String) {
    debug!("Creating empty RWFS {}", target);

    let to = format!("test/{}.rwimage", &target);

    let k = match mode.as_str() {
        "enc" => {
            let mut k = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut k);
            Some(k)
        }
        "int" => {
            None
        }
        _ => panic!("unrecognized fsmode"),
    };

    let mode = rw::create_empty(
        Path::new(&to),
        k,
    ).unwrap();
    match &mode {
        FSMode::IntegrityOnly(hash) => {
            let s = hex::encode_upper(hash);
            println!("Built in IntegrityOnly Mode:");
            println!("Hash: {}", s);
        }
        FSMode::Encrypted(key, mac) => {
            assert_eq!(k.unwrap(), *key);
            println!("Built in Encrypted Mode:");
            let k = hex::encode_upper(key);
            let m = hex::encode_upper(mac);
            println!("Key: {}", k);
            println!("Mac: {}", m);
        }
    }
    // save mode to file
    let name = format!("test/{}.mode", target);
    let _ = fs::remove_file(name.clone());
    let mut f = OpenOptions::new().write(true).create_new(true).open(name).unwrap();
    let written = f.write(unsafe {
        std::slice::from_raw_parts(
            &mode as *const FSMode as *const u8,
            std::mem::size_of::<FSMode>(),
        )
    }).unwrap();
    assert_eq!(written, std::mem::size_of::<FSMode>());
}

fn main() {
    if cfg!(debug_assertions) {
        env::set_var("RUST_BACKTRACE", "1");
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    }

    let args: Vec<String> = env::args().collect();
    assert!(args.len() >= 4);
    let tp = args[1].clone();
    let mode = args[2].clone();
    let target = args[3].clone();

    match tp.as_str() {
        "ro" => build_ro(mode, target),
        "rw" => build_rw(mode, target),
        "empty" => build_empty(mode, target),
        _ => panic!("unrecognized type {}", tp),
    }
}
