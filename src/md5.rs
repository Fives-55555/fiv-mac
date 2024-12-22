const MD_BUFFER: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
const SINCONST: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const SHIFT: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

macro_rules! help {
    ($input:expr,$i:expr,$x:expr) => {
        u32::from_le_bytes([
            $input[$i * 64 + $x * 4],
            $input[$i * 64 + $x * 4 + 1],
            $input[$i * 64 + $x * 4 + 2],
            $input[$i * 64 + $x * 4 + 3],
        ])
    };
}

struct MD5State {
    input: Vec<u8>,
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

pub fn md5(mut input: Vec<u8>) -> Vec<u8> {
    let length: u64 = (input.len() * 8) as u64;
    input.push(0b1 << 7);
    while input.len() % 64 != 56 {
        input.push(0);
    }

    input.extend_from_slice(&length.to_le_bytes());

    let mut state = MD5State {
        input: input,
        a: MD_BUFFER[0],
        b: MD_BUFFER[1],
        c: MD_BUFFER[2],
        d: MD_BUFFER[3],
    };

    for i in 0..state.input.len() / 64 {
        let prev_a = state.a;
        let prev_b = state.b;
        let prev_c = state.c;
        let prev_d = state.d;

        round1(&mut state, i);
        round2(&mut state, i);
        round3(&mut state, i);
        round4(&mut state, i);

        state.a = state.a.wrapping_add(prev_a);
        state.b = state.b.wrapping_add(prev_b);
        state.c = state.c.wrapping_add(prev_c);
        state.d = state.d.wrapping_add(prev_d);
    }
    let hash = [
        state.a.to_le_bytes(),
        state.b.to_le_bytes(),
        state.c.to_le_bytes(),
        state.d.to_le_bytes(),
    ]
    .concat();
    hash
}

fn round1(state: &mut MD5State, i: usize) {
    let a  = &mut state.a;
    let b  = &mut state.b;
    let c  = &mut state.c;
    let d  = &mut state.d;
    let input = &state.input;
    f(a, b, c, d, help!(input, i, 0), SHIFT[0], SINCONST[0]);
    f(d, a, b, c, help!(input, i, 1), SHIFT[1], SINCONST[1]);
    f(c, d, a, b, help!(input, i, 2), SHIFT[2], SINCONST[2]);
    f(b, c, d, a, help!(input, i, 3), SHIFT[3], SINCONST[3]);
    f(a, b, c, d, help!(input, i, 4), SHIFT[0], SINCONST[4]);
    f(d, a, b, c, help!(input, i, 5), SHIFT[1], SINCONST[5]);
    f(c, d, a, b, help!(input, i, 6), SHIFT[2], SINCONST[6]);
    f(b, c, d, a, help!(input, i, 7), SHIFT[3], SINCONST[7]);
    f(a, b, c, d, help!(input, i, 8), SHIFT[0], SINCONST[8]);
    f(d, a, b, c, help!(input, i, 9), SHIFT[1], SINCONST[9]);
    f(c, d, a, b, help!(input, i, 10), SHIFT[2], SINCONST[10]);
    f(b, c, d, a, help!(input, i, 11), SHIFT[3], SINCONST[11]);
    f(a, b, c, d, help!(input, i, 12), SHIFT[0], SINCONST[12]);
    f(d, a, b, c, help!(input, i, 13), SHIFT[1], SINCONST[13]);
    f(c, d, a, b, help!(input, i, 14), SHIFT[2], SINCONST[14]);
    f(b, c, d, a, help!(input, i, 15), SHIFT[3], SINCONST[15]);
}

fn round2(state: &mut MD5State, i: usize) {
    let a  = &mut state.a;
    let b  = &mut state.b;
    let c  = &mut state.c;
    let d  = &mut state.d;
    let input = &state.input;
    g(a, b, c, d, help!(input, i, 1), SHIFT[4], SINCONST[16]);
    g(d, a, b, c, help!(input, i, 6), SHIFT[5], SINCONST[17]);
    g(c, d, a, b, help!(input, i, 11), SHIFT[6], SINCONST[18]);
    g(b, c, d, a, help!(input, i, 0), SHIFT[7], SINCONST[19]);
    g(a, b, c, d, help!(input, i, 5), SHIFT[4], SINCONST[20]);
    g(d, a, b, c, help!(input, i, 10), SHIFT[5], SINCONST[21]);
    g(c, d, a, b, help!(input, i, 15), SHIFT[6], SINCONST[22]);
    g(b, c, d, a, help!(input, i, 4), SHIFT[7], SINCONST[23]);
    g(a, b, c, d, help!(input, i, 9), SHIFT[4], SINCONST[24]);
    g(d, a, b, c, help!(input, i, 14), SHIFT[5], SINCONST[25]);
    g(c, d, a, b, help!(input, i, 3), SHIFT[6], SINCONST[26]);
    g(b, c, d, a, help!(input, i, 8), SHIFT[7], SINCONST[27]);
    g(a, b, c, d, help!(input, i, 13), SHIFT[4], SINCONST[28]);
    g(d, a, b, c, help!(input, i, 2), SHIFT[5], SINCONST[29]);
    g(c, d, a, b, help!(input, i, 7), SHIFT[6], SINCONST[30]);
    g(b, c, d, a, help!(input, i, 12), SHIFT[7], SINCONST[31]);
}

fn round3(state:  &mut MD5State, i: usize) {
    let a  = &mut state.a;
    let b  = &mut state.b;
    let c  = &mut state.c;
    let d  = &mut state.d;
    let input = &state.input;
    h(a, b, c, d, help!(input, i, 5), SHIFT[8], SINCONST[32]);
    h(d, a, b, c, help!(input, i, 8), SHIFT[9], SINCONST[33]);
    h(c, d, a, b, help!(input, i, 11), SHIFT[10], SINCONST[34]);
    h(b, c, d, a, help!(input, i, 14), SHIFT[11], SINCONST[35]);
    h(a, b, c, d, help!(input, i, 1), SHIFT[8], SINCONST[36]);
    h(d, a, b, c, help!(input, i, 4), SHIFT[9], SINCONST[37]);
    h(c, d, a, b, help!(input, i, 7), SHIFT[10], SINCONST[38]);
    h(b, c, d, a, help!(input, i, 10), SHIFT[11], SINCONST[39]);
    h(a, b, c, d, help!(input, i, 13), SHIFT[8], SINCONST[40]);
    h(d, a, b, c, help!(input, i, 0), SHIFT[9], SINCONST[41]);
    h(c, d, a, b, help!(input, i, 3), SHIFT[10], SINCONST[42]);
    h(b, c, d, a, help!(input, i, 6), SHIFT[11], SINCONST[43]);
    h(a, b, c, d, help!(input, i, 9), SHIFT[8], SINCONST[44]);
    h(d, a, b, c, help!(input, i, 12), SHIFT[9], SINCONST[45]);
    h(c, d, a, b, help!(input, i, 15), SHIFT[10], SINCONST[46]);
    h(b, c, d, a, help!(input, i, 2), SHIFT[11], SINCONST[47]);
}
fn round4(state:  &mut MD5State, i: usize) {
    let a  = &mut state.a;
    let b  = &mut state.b;
    let c  = &mut state.c;
    let d  = &mut state.d;
    let input = &state.input;
    fi(a, b, c, d, help!(input, i, 0), SHIFT[12], SINCONST[48]);
    fi(d, a, b, c, help!(input, i, 7), SHIFT[13], SINCONST[49]);
    fi(c, d, a, b, help!(input, i, 14), SHIFT[14], SINCONST[50]);
    fi(b, c, d, a, help!(input, i, 5), SHIFT[15], SINCONST[51]);
    fi(a, b, c, d, help!(input, i, 12), SHIFT[12], SINCONST[52]);
    fi(d, a, b, c, help!(input, i, 3), SHIFT[13], SINCONST[53]);
    fi(c, d, a, b, help!(input, i, 10), SHIFT[14], SINCONST[54]);
    fi(b, c, d, a, help!(input, i, 1), SHIFT[15], SINCONST[55]);
    fi(a, b, c, d, help!(input, i, 8), SHIFT[12], SINCONST[56]);
    fi(d, a, b, c, help!(input, i, 15), SHIFT[13], SINCONST[57]);
    fi(c, d, a, b, help!(input, i, 6), SHIFT[14], SINCONST[58]);
    fi(b, c, d, a, help!(input, i, 13), SHIFT[15], SINCONST[59]);
    fi(a, b, c, d, help!(input, i, 4), SHIFT[12], SINCONST[60]);
    fi(d, a, b, c, help!(input, i, 11), SHIFT[13], SINCONST[61]);
    fi(c, d, a, b, help!(input, i, 2), SHIFT[14], SINCONST[62]);
    fi(b, c, d, a, help!(input, i, 9), SHIFT[15], SINCONST[63]);
}

fn f(a: &mut u32, x: &mut u32, y: &mut u32, z: &mut u32, element: u32, shift: u32, sincon: u32) {
    *a = a
        .wrapping_add((*x & *y) | ((!*x) & *z))
        .wrapping_add(element)
        .wrapping_add(sincon);
    *a = a.rotate_left(shift);
    *a = a.wrapping_add(*x);
}

fn g(a: &mut u32, x: &mut u32, y: &mut u32, z: &mut u32, element: u32, shift: u32, sincon: u32) {
    *a = a
        .wrapping_add((*x & *z) | (*y & (!*z)))
        .wrapping_add(element)
        .wrapping_add(sincon);
    *a = a.rotate_left(shift);
    *a = a.wrapping_add(*x);
}

fn h(a: &mut u32, x: &mut u32, y: &mut u32, z: &mut u32, element: u32, shift: u32, sincon: u32) {
    *a = a
        .wrapping_add(*x ^ *y ^ *z)
        .wrapping_add(element)
        .wrapping_add(sincon);
    *a = a.rotate_left(shift);
    *a = a.wrapping_add(*x);
}

fn fi(a: &mut u32, x: &mut u32, y: &mut u32, z: &mut u32, element: u32, shift: u32, sincon: u32) {
    *a = a
        .wrapping_add(*y ^ (*x | (!*z)))
        .wrapping_add(element)
        .wrapping_add(sincon);
    *a = a.rotate_left(shift);
    *a = a.wrapping_add(*x);
}

#[test]
fn test() {
    assert_eq!(
        md5(vec![]),
        vec![
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e
        ]
    );
    assert_eq!(
        md5(vec![b'a']),
        vec![
            0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77,
            0x26, 0x61
        ]
    );
    assert_eq!(
        md5(vec![b'a', b'b', b'c']),
        vec![
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72
        ]
    );
    assert_eq!(
        md5(vec![
            b'm', b'e', b's', b's', b'a', b'g', b'e', b' ', b'd', b'i', b'g', b'e', b's', b't'
        ]),
        vec![
            0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1,
            0x61, 0xd0
        ]
    );
    assert_eq!(
        md5(vec![
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
            b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z'
        ]),
        vec![
            0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67,
            0xe1, 0x3b
        ]
    );
    assert_eq!(
        md5(vec![
            b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N',
            b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b',
            b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p',
            b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3',
            b'4', b'5', b'6', b'7', b'8', b'9'
        ]),
        vec![
            0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41,
            0x9d, 0x9f
        ]
    );
    assert_eq!(
        md5(vec![
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4',
            b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
            b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2',
            b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6',
            b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'
        ]),
        vec![
            0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07,
            0xb6, 0x7a
        ]
    );
}
