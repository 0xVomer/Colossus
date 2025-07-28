const PROTOBUF_BASE_DIRECTORY: &str = "src/proto/specs";

const PROTOBUF_FILES: [&str; 1] = ["types"];

const PROTOS_OUTPUT_DIR: &str = "protos";

fn build_protobufs() {
    let mut protobuf_files = Vec::with_capacity(PROTOBUF_FILES.len());

    for file in PROTOBUF_FILES.iter() {
        let proto_file = format!("{PROTOBUF_BASE_DIRECTORY}/{file}.proto");
        println!("cargo:rerun-if-changed={proto_file}");
        protobuf_files.push(proto_file);
    }

    protobuf_codegen::Codegen::new()
        .pure()
        .includes([PROTOBUF_BASE_DIRECTORY])
        .inputs(&protobuf_files)
        .cargo_out_dir(PROTOS_OUTPUT_DIR)
        .run_from_script();
}

fn main() {
    build_protobufs();
}
