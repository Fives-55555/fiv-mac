use crate::MAC;

use super::padding_v1;

pub struct SHA1 {}

impl MAC for SHA1 {
    const BLOCK_SIZE: u16 = 512;
    const DIGEST_SIZE: u16 = 160;
    const WORD_SIZE: u16 = 32;
    const MAX_SIZE: usize = u64::MAX as usize;

    type Digest = Result<[u8; 20], ()>;

    fn hash(mut v: Vec<u8>) -> Self::Digest {
        padding_v1(&mut v)?;

        let mut w_block: [u32; 80] = [0; 80];

        let mut a: u32 = SHA1::INIT[0];
        let mut b: u32 = SHA1::INIT[1];
        let mut c: u32 = SHA1::INIT[2];
        let mut d: u32 = SHA1::INIT[3];
        let mut e: u32 = SHA1::INIT[4];

        for i in 0..v.len() / 64 {
            for x in 0..16 {
                w_block[x] = u32::from_be_bytes([
                    v[i * 64 + x * 4],
                    v[i * 64 + x * 4 + 1],
                    v[i * 64 + x * 4 + 2],
                    v[i * 64 + x * 4 + 3],
                ]);
            }
            for x in 16..80 {
                w_block[x] = (w_block[x - 3] ^ w_block[x - 8] ^ w_block[x - 14] ^ w_block[x - 16])
                    .rotate_left(1);
            }

            let (bef_a, bef_b, bef_c, bef_d, bef_e) = (a, b, c, d, e);

            for x in 0..80 {
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(e)
                    .wrapping_add(w_block[x])
                    .wrapping_add(SHA1::f(x, b, c, d));
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }

            a = a.wrapping_add(bef_a);
            b = b.wrapping_add(bef_b);
            c = c.wrapping_add(bef_c);
            d = d.wrapping_add(bef_d);
            e = e.wrapping_add(bef_e);
        }
        let a = a.to_le_bytes();
        let b = b.to_le_bytes();
        let c = c.to_le_bytes();
        let d = d.to_le_bytes();
        let e = e.to_le_bytes();
        let hash = [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1],
            d[2], d[3], e[0], e[1], e[2], e[3],
        ];
        Ok(hash)
    }
}

impl SHA1 {
    const INIT: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    fn f(i: usize, x: u32, y: u32, z: u32) -> u32 {
        match i {
            ..20 => ((x & y) ^ (!x & z)).wrapping_add(0x5a827999),
            ..40 => (x ^ y ^ z).wrapping_add(0x6ed9eba1),
            ..60 => ((x & y) ^ (x & z) ^ (y & z)).wrapping_add(0x8f1bbcdc),
            ..80 => (x ^ y ^ z).wrapping_add(0xca62c1d6),
            _ => panic!("1mpossible State"),
        }
    }
}

#[test]
fn sha1() {
    assert_eq!(
        SHA1::hash(vec![]),
        Ok([
            0xEE, 0xA3, 0x39, 0xDA, 0x0D, 0x4B, 0x6B, 0x5E, 0xEF, 0xBF, 0x55, 0x32, 0x90, 0x18,
            0x60, 0x95, 0x09, 0x07, 0xD8, 0xAF
        ])
    );
    assert_eq!(
        SHA1::hash(vec![b'a']),
        Ok([
            0x37, 0xE4, 0xF7, 0x86, 0xFC, 0xA7, 0xA5, 0xFA, 0xDC, 0x1D, 0x5D, 0xE1, 0xEA, 0xEA,
            0xEA, 0xB9, 0xB8, 0x67, 0x76, 0x37
        ])
    );
    assert_eq!(
        SHA1::hash(vec![b'a', b'b', b'c']),
        Ok([
            0x36, 0x3E, 0x99, 0xA9, 0x6A, 0x81, 0x06, 0x47, 0x71, 0x25, 0x3E, 0xBA, 0x6C, 0xC2,
            0x50, 0x78, 0x9D, 0xD8, 0xD0, 0x9C
        ])
    );
    assert_eq!(
        SHA1::hash(vec![
            b'm', b'e', b's', b's', b'a', b'g', b'e', b' ', b'd', b'i', b'g', b'e', b's', b't'
        ]),
        Ok([
            0xCE, 0x52, 0x22, 0xC1, 0x99, 0xE8, 0x8B, 0xDA, 0x29, 0xA0, 0x5F, 0x4D, 0x1C, 0x23,
            0x47, 0x0A, 0xE3, 0xAA, 0x16, 0x1D
        ])
    );
    assert_eq!(
        SHA1::hash(vec![
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
            b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z'
        ]),
        Ok([
            0x7B, 0x0C, 0xD1, 0x32, 0x70, 0x65, 0xF9, 0x8C, 0x37, 0xCE, 0x04, 0xCA, 0x84, 0x9D,
            0xA1, 0xF2, 0x89, 0x3A, 0x0D, 0x24
        ])
    );
    assert_eq!(
        SHA1::hash(vec![
            b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N',
            b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b',
            b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p',
            b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3',
            b'4', b'5', b'6', b'7', b'8', b'9'
        ]),
        Ok([
            0x7B, 0x45, 0x1C, 0x76, 0xD2, 0x14, 0x3B, 0xF7, 0x65, 0x92, 0x9E, 0x7E, 0x4D, 0x4B,
            0x6F, 0xC4, 0x40, 0xF9, 0x11, 0xDA
        ])
    );
    assert_eq!(
        SHA1::hash(vec![
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4',
            b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
            b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2',
            b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6',
            b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'
        ]),
        Ok([
            0x70, 0xF5, 0xAB, 0x50, 0x90, 0x09, 0x15, 0x6A, 0x5E, 0x2C, 0x8B, 0xA0, 0xE5, 0xA0,
            0x0F, 0xA4, 0x32, 0x47, 0x55, 0x85
        ])
    );
}
