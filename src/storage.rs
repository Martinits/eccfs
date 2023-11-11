use std::path::Path;
use std::sync::Arc;

pub trait Storage: Send + Sync {
    fn open(self, path: &Path, start: u64, length: u64) -> Arc<dyn Storage>;

    fn create(self, path: &Path);

    fn read_blk(self, pos: u64);

    fn write_blk(self, pos: u64);

    fn close(self);

    fn remove(self);
}

struct FileStorage {

}

struct DeviceStorage {

}
