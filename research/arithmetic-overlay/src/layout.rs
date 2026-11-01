pub const HEIGHT: usize = 8192;
pub const LOW: usize = 64;
pub const HIGH: usize = 128;
pub const PRODUCT_MODE: usize = LOW + HIGH;
pub const HINT_MODE: usize = PRODUCT_MODE + 1;
pub const BANK: usize = HINT_MODE + 1;
pub const BANK_WIDTH: usize = 8 * super::mul::WIDTH;
pub const HINT_WIDTH: usize = 8 * super::hints::WIDTH;
pub const SOURCE: usize = BANK + BANK_WIDTH;
pub const PRODUCT_SINK: usize = SOURCE + 8 * 4;
pub const HINT_SINK: usize = PRODUCT_SINK + 8;
pub const WIDTH: usize = HINT_SINK + 8;
pub const PUBLIC_VALUES: usize = 16;
const _: () =
    assert!(super::mul::VALUES == 0 && BANK_WIDTH == 1688 && HINT_WIDTH == 1000 && WIDTH == 1930);
