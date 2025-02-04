use crate::types::Program;
use base64::{self, Engine};
use serde_json;
use std::fs;

pub fn program_at_path(acir_path: String) -> Program {
    let json_string =
        fs::read_to_string(acir_path).expect("There was a problem reading the file content");
    let json_str: &str = &json_string;
    let json: serde_json::Value =
        serde_json::from_str(json_str).expect("There was a problem parsing the json program");
    let Some(bytecode_str) = json["bytecode"].as_str() else {
        panic!("Expected a different circuit format")
    };
    let bytecode: &[u8] = &base64::prelude::BASE64_STANDARD
        .decode(bytecode_str)
        .expect("There was a problem decoding the program from base 64");
    let program = Program::deserialize_program(bytecode);
    program.unwrap()
}
