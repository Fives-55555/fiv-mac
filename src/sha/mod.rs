pub mod sha1;

pub use sha1::SHA1;

fn padding_v1(v: &mut Vec<u8>) -> Result<(), ()> {
    let len = v.len() * 8;
    if len > u64::MAX as usize {
        return Err(());
    }
    v.push(1 << 7);
    while (v.len() % 64) != 56 {
        v.push(0);
    }
    v.extend_from_slice(&(len as u64).to_be_bytes());
    Ok(())
}

fn padding_v2(v: &mut Vec<u8>) -> Result<(), ()> {
    let len = v.len() * 8;
    if len > u128::MAX as usize {
        return Err(());
    }
    v.push(1 << 7);
    while (v.len() % 128) != 112 {
        v.push(0);
    }
    v.extend_from_slice(&(len as u128).to_be_bytes());
    Ok(())
}
