use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

pub trait MemoryOps<A> {
    fn read_bytes(&self, addr: A, buf: &mut [u8]) -> Result<usize, String>;
    fn write_bytes(&self, addr: A, buf: &[u8]) -> Result<usize, String>;

    fn read<T: Copy + FromZeros + FromBytes + IntoBytes>(&self, addr: A) -> Result<T, String> {
        let mut obj = T::new_zeroed();

        let slice = obj.as_mut_bytes();
        self.read_bytes(addr, slice)?;

        Ok(obj)
    }

    fn write<T: Copy + IntoBytes + Immutable>(&self, addr: A, val: &T) -> Result<usize, String> {
        let slice = val.as_bytes();
        self.write_bytes(addr, slice)
    }
}
