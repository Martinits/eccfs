#[repr(C)]
struct DInode {
    size: u64,
    uid: u32,
    gid: u32,
    atime: u32,
    ctime: u32,
    mtime: u32,
    mode: u16,
    nlinks: u16,
}
