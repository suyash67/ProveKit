use {
    crate::SmolHasher,
    hex_literal::hex,
    ruint::{aliases::U256, uint},
    std::{fmt::Display, u64},
};

const MODULUS: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);
const MOD_INV: u64 = 14042775128853446655;
const RC: [U256; 8] = uint! {[
    17829420340877239108687448009732280677191990375576158938221412342251481978692_U256,
    5852100059362614845584985098022261541909346143980691326489891671321030921585_U256,
    17048088173265532689680903955395019356591870902241717143279822196003888806966_U256,
    71577923540621522166602308362662170286605786204339342029375621502658138039_U256,
    1630526119629192105940988602003704216811347521589219909349181656165466494167_U256,
    7807402158218786806372091124904574238561123446618083586948014838053032654983_U256,
    13329560971460034925899588938593812685746818331549554971040309989641523590611_U256,
    16971509144034029782226530622087626979814683266929655790026304723118124142299_U256,
]};
const SBOX: [u8; 256] = hex!("00020416080a2c2e10121406585a5c5e20222436282a0c0eb0b2b4a6b8babcbe40424456484a6c6e50525446181a1c1e61636577696b4d4f71737567797b7d7f80828496888aacae90929486d8dadcdea0a2a4b6a8aa8c8e30323426383a3c3ec2c0c6d4cac8eeecd2d0d6c49a989e9ce2e0e6f4eae8ceccf2f0f6e4faf8fefc010b051709032d2f111b150759535d5f212b253729230d0fb1bbb5a7b9b3bdbf414b455749436d6f515b554719131d1f606a647668624c4e707a746678727c7e858b81978d83a9af959b9187ddd3d9dfa5aba1b7ada3898f353b31273d33393fc5cbc1d7cdc3e9efd5dbd1c79d93999fe5ebe1f7ede3c9cff5fbf1e7fdf3f9ff");

const SBOX_SHIFT_1: u64 = 0x8080808080808080;
const SBOX_SHIFT_2: u64 = 0xc0c0c0c0c0c0c0c0;
const SBOX_SHIFT_3: u64 = 0xe0e0e0e0e0e0e0e0;
const SBOX_SHIFT_4: u64 = 0xf0f0f0f0f0f0f0f0;

const SBOX_SHIFT_1_BAR: u64 = !SBOX_SHIFT_1;
const SBOX_SHIFT_2_BAR: u64 = !SBOX_SHIFT_2;
const SBOX_SHIFT_3_BAR: u64 = !SBOX_SHIFT_3;
const SBOX_SHIFT_4_BAR: u64 = !SBOX_SHIFT_4;

const SBOX_TABLE: [u8; 256] = [
    0, 2, 4, 22, 8, 10, 44, 46, 16, 18, 20, 6, 88, 90, 92, 94, 32, 34, 36, 54, 40, 42, 12, 14, 176,
    178, 180, 166, 184, 186, 188, 190, 64, 66, 68, 86, 72, 74, 108, 110, 80, 82, 84, 70, 24, 26,
    28, 30, 97, 99, 101, 119, 105, 107, 77, 79, 113, 115, 117, 103, 121, 123, 125, 127, 128, 130,
    132, 150, 136, 138, 172, 174, 144, 146, 148, 134, 216, 218, 220, 222, 160, 162, 164, 182, 168,
    170, 140, 142, 48, 50, 52, 38, 56, 58, 60, 62, 194, 192, 198, 212, 202, 200, 238, 236, 210,
    208, 214, 196, 154, 152, 158, 156, 226, 224, 230, 244, 234, 232, 206, 204, 242, 240, 246, 228,
    250, 248, 254, 252, 1, 11, 5, 23, 9, 3, 45, 47, 17, 27, 21, 7, 89, 83, 93, 95, 33, 43, 37, 55,
    41, 35, 13, 15, 177, 187, 181, 167, 185, 179, 189, 191, 65, 75, 69, 87, 73, 67, 109, 111, 81,
    91, 85, 71, 25, 19, 29, 31, 96, 106, 100, 118, 104, 98, 76, 78, 112, 122, 116, 102, 120, 114,
    124, 126, 133, 139, 129, 151, 141, 131, 169, 175, 149, 155, 145, 135, 221, 211, 217, 223, 165,
    171, 161, 183, 173, 163, 137, 143, 53, 59, 49, 39, 61, 51, 57, 63, 197, 203, 193, 215, 205,
    195, 233, 239, 213, 219, 209, 199, 157, 147, 153, 159, 229, 235, 225, 247, 237, 227, 201, 207,
    245, 251, 241, 231, 253, 243, 249, 255,
];

pub struct Skyscraper;

impl Display for Skyscraper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("skyscraper-bn254-ruint")
    }
}

impl SmolHasher for Skyscraper {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let a = from_bytes(&message[0..32]);
            let b = from_bytes(&message[32..64]);
            let c = compress(a, b);
            hash.copy_from_slice(c.as_le_slice());
        }
    }
}

fn from_bytes(bytes: &[u8]) -> U256 {
    reduce(U256::from_le_bytes::<32>(bytes.try_into().unwrap()))
}

fn reduce(mut n: U256) -> U256 {
    loop {
        let (reduced, borrow) = n.overflowing_sub(MODULUS);
        if borrow {
            return n;
        } else {
            n = reduced;
        }
    }
}

fn add_2(a: U256, b: U256) -> U256 {
    let (sum, carry) = a.overflowing_add(b);
    let (reduced, borrow) = sum.overflowing_sub(MODULUS);
    if carry | !borrow {
        reduced
    } else {
        sum
    }
}

fn add_3(a: U256, b: U256, c: U256) -> U256 {
    add_2(add_2(a, b), c)
}

fn compress(l: U256, r: U256) -> U256 {
    let a = l;
    let (l, r) = (add_2(r, square(l)), l);
    let (l, r) = (add_3(r, square(l), RC[0]), l);
    let (l, r) = (add_3(r, bar(l), RC[1]), l);
    let (l, r) = (add_3(r, bar(l), RC[2]), l);
    let (l, r) = (add_3(r, square(l), RC[3]), l);
    let (l, r) = (add_3(r, square(l), RC[4]), l);
    let (l, r) = (add_3(r, bar(l), RC[5]), l);
    let (l, r) = (add_3(r, bar(l), RC[6]), l);
    let (l, r) = (add_3(r, square(l), RC[7]), l);
    let (l, _) = (add_2(r, square(l)), l);
    add_2(l, a)
}

fn compress_prime(l: U256, r: U256) -> U256 {
    let a = l;
    let (l, r) = (add_2(r, square(l)), l);
    let (l, r) = (add_3(r, square(l), RC[0]), l);
    let (l, r) = (add_3(r, bar_on_limbs(l), RC[1]), l);
    let (l, r) = (add_3(r, bar_on_limbs(l), RC[2]), l);
    let (l, r) = (add_3(r, square(l), RC[3]), l);
    let (l, r) = (add_3(r, square(l), RC[4]), l);
    let (l, r) = (add_3(r, bar_on_limbs(l), RC[5]), l);
    let (l, r) = (add_3(r, bar_on_limbs(l), RC[6]), l);
    let (l, r) = (add_3(r, square(l), RC[7]), l);
    let (l, _) = (add_2(r, square(l)), l);
    add_2(l, a)
}

fn square(n: U256) -> U256 {
    n.square_redc(MODULUS, MOD_INV)
}

fn bar_on_limbs(mut n: U256) -> U256 {
    let n_limbs = unsafe { n.as_limbs_mut() };

    // Rotate left by 2 places (to swap the limbs)
    n_limbs.rotate_left(2);

    // Apply sbox
    n_limbs.iter_mut().for_each(|limb| *limb = sbox_big(*limb));

    // Recompose and modular reduce
    reduce(n)
}

fn bar(mut n: U256) -> U256 {
    // Decompose into raw bytes.
    let bytes = unsafe { n.as_le_slice_mut() };

    // Cyclic rotate by 16 bytes.
    let (left, right) = bytes.split_at_mut(16);
    left.swap_with_slice(right);

    // Apply SBox.
    bytes.iter_mut().for_each(|b| *b = sbox(*b));

    // Recompose and modular reduce
    reduce(n)
}

fn sbox(v: u8) -> u8 {
    (v ^ ((!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3))).rotate_left(1)
}

fn sbox_big(input: u64) -> u64 {
    let input_1_bit = input & SBOX_SHIFT_1;
    let input_2_bit = input & SBOX_SHIFT_2;
    let input_3_bit = input & SBOX_SHIFT_3;
    let input_4_bit = input & SBOX_SHIFT_4;
    let in_rotate_left_1 = ((input & SBOX_SHIFT_1_BAR) << 1) ^ (input_1_bit >> 7);
    let in_rotate_left_2 = ((input & SBOX_SHIFT_2_BAR) << 2) ^ (input_2_bit >> 6);
    let in_rotate_left_3 = ((input & SBOX_SHIFT_3_BAR) << 3) ^ (input_3_bit >> 5);
    let in_rotate_left_4 = ((input & SBOX_SHIFT_4_BAR) << 4) ^ (input_4_bit >> 4);

    in_rotate_left_1 ^ ((in_rotate_left_2 ^ u64::MAX) & in_rotate_left_3 & in_rotate_left_4)
}

// WARNING: Just for testing
fn sbox_dist(v: u8) -> u8 {
    v.rotate_left(1) ^ ((!v).rotate_left(2) & v.rotate_left(3) & v.rotate_left(4))
}

// WARNING: Just for testing
fn bitop(v: u8) -> u8 {
    (!v).rotate_left(1) & v.rotate_left(2) & v.rotate_left(3)
}

#[cfg(test)]
mod tests {
    use {super::*, ruint::uint, std::collections::HashSet};

    #[test]
    fn test_sbox() {
        assert_eq!(sbox(0xcd), 0xd3);
        assert_eq!(sbox(0x17), 0x0e);
    }

    #[test]
    fn test_sbox_table() {
        for i in 0u8..=255 {
            assert_eq!(sbox(i), SBOX_TABLE[i as usize]);
            assert_eq!(sbox(i), sbox_dist(i));
        }
    }

    #[test]
    fn test_sbox_large() {
        let number: u64 = 0x1122334455667788;
        let mut output_bytes: [u8; 8] = number.to_be_bytes();
        output_bytes.iter_mut().for_each(|b| *b = sbox_dist(*b));
        assert_eq!(output_bytes, sbox_big(number).to_be_bytes());
    }

    #[test]
    fn test_bitop_table() {
        let mut unique_values = HashSet::new();
        for i in 0u8..=255 {
            println!("b({}) = {}", i, bitop(i));
            unique_values.insert(bitop(i));
        }

        // Print the unique values
        let mut unique_vec: Vec<u8> = unique_values.into_iter().collect();
        unique_vec.sort();
        println!("unique size = {}", unique_vec.len());
        println!("Unique values: {:?}", unique_vec);
    }

    #[test]
    fn test_square() {
        uint! {
            assert_eq!(square(0_U256), 0_U256);
            assert_eq!(square(1_U256),
                9915499612839321149637521777990102151350674507940716049588462388200839649614_U256);
            assert_eq!(square(2_U256),
                17773755579518009376303681366703133516854333631346829854655645366227550102839_U256);
            assert_eq!(
                square(1104450765605124869545290932753078120560901577733272073477890658487831733222_U256),
                20498050724266033890829404465405035543297153733520482423774420418741549228506_U256);
        }
    }

    #[test]
    fn test_bar() {
        uint! {
            assert_eq!(bar(0_U256), 0_U256);
            assert_eq!(bar(1_U256),
                680564733841876926926749214863536422912_U256);
            assert_eq!(bar(2_U256),
                1361129467683753853853498429727072845824_U256);
            assert_eq!(
                bar(4111585712030104139416666328230194227848755236259444667527487224433891325648_U256),
                18867677047139790809471719918880601980605904427073186248909139907505620573990_U256);
        }
    }

    #[test]
    fn test_bar_on_limbs() {
        uint! {
            assert_eq!(bar(0_U256), bar_on_limbs(0_U256));
            assert_eq!(bar(1_U256), bar_on_limbs(1_U256));
            assert_eq!(bar(2_U256), bar_on_limbs(2_U256));
            assert_eq!(
                bar(
                    4111585712030104139416666328230194227848755236259444667527487224433891325648_U256
                ),
                bar_on_limbs(
                    4111585712030104139416666328230194227848755236259444667527487224433891325648_U256
                ));
        }
    }

    #[test]
    fn test_compress() {
        uint! {
            assert_eq!(compress(
                21614608883591910674239883101354062083890746690626773887530227216615498812963_U256,
                9813154100006487150380270585621895148484502414032888228750638800367218873447_U256,
            ),
            3583228880285179354728993622328037400470978495633822008876840172083178912457_U256
            );
        }
    }

    #[test]
    fn test_compress_prime() {
        uint! {
            assert_eq!(
            compress(
                21614608883591910674239883101354062083890746690626773887530227216615498812963_U256,
                9813154100006487150380270585621895148484502414032888228750638800367218873447_U256,
            ),
            compress_prime(
                21614608883591910674239883101354062083890746690626773887530227216615498812963_U256,
                9813154100006487150380270585621895148484502414032888228750638800367218873447_U256,
            )
            );
        }
    }
}
