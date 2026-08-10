use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct Tx {
    version: u32,
    marker: Option<u8>,
    flag: Option<u8>,
    input_count: usize,
    inputs: Vec<Input>,
    output_count: usize,
    outputs: Vec<Output>,
    lock_time: u32,
    witness: Option<Witness>,
}

#[derive(Debug, Serialize)]
pub struct Input {
    tx_id: [u8; 32],
    v_out: u32,
    script_sig_size: usize,
    script_sig: Option<Vec<u8>>,
    sequence: u32,
}

#[derive(Debug, Serialize)]
pub struct Output {
    value: u64,
    script_pub_key_size: usize,
    script_pub_key: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Witness {
    stack_items_size: usize,
    stack_items: Option<Vec<WitnessStackItem>>,
}

#[derive(Debug, Serialize)]
pub struct WitnessStackItem {
    item_size: usize,
    item: Vec<u8>,
}
