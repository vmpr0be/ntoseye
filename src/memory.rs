use crate::backend::MemoryOps;
use crate::types::*;

const PAGE_OFFSET_SIZE: u32 = 12;

// PageFrameNumber
const PMASK: u64 = (!0xFu64 << 8) & 0xFFFFFFFFFu64;

// 'a = lifetime of the borrow of the backend
//  B = any type that implements phys mem
pub struct AddressSpace<'a, B: MemoryOps<PhysAddr>> {
    backend: &'a B,
    dtb: Dtb,
}

pub const fn sign_extend_48bit(address: u64) -> u64 {
    if address & 0x0000_8000_0000_0000 != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    pub fn new(backend: &'a B, dtb: Dtb) -> Self {
        Self { backend, dtb }
    }

    fn read_entry(&self, base: u64, index: u64) -> Result<PageTableEntry, String> {
        self.backend.read(PhysAddr(8 * index + base))
    }

    // TODO lots of bad casting here, needs to be rewritten
    pub fn virt_to_phys(&self, vaddr: VirtAddr) -> Result<PhysAddr, String> {
        let pdpe = self.read_entry(self.dtb.0.0, vaddr.pdp_index())?;
        if !pdpe.is_present() {
            return Err("bad pdpe".into());
        }

        let pde = self.read_entry(pdpe.0 & PMASK, vaddr.pd_index())?;
        if !pde.is_present() {
            return Err("bad pde".into());
        }

        if pde.is_large_page() {
            return Ok(PhysAddr(
                (pde.0 & (!0u64 << 42 >> 12)) + (vaddr.0 & !(!0u64 << 30)),
            ));
        }

        let pte_address = self.read_entry(pde.0 & PMASK, vaddr.pt_index())?;
        if !pte_address.is_present() {
            return Err("bad pte address".into());
        }

        if pte_address.is_large_page() {
            return Ok(PhysAddr(
                (pte_address.0 & PMASK) + (vaddr.0 & !(!0u64 << 21)),
            ));
        }

        let paddr = self.read_entry(pte_address.0 & PMASK, vaddr.pte_index())?;
        let paddr = paddr.0 & PMASK;
        if paddr == 0 {
            return Err("bad physical page".into());
        }

        Ok(PhysAddr(paddr + vaddr.page_offset()))
    }
}

impl<'a, B: MemoryOps<PhysAddr>> MemoryOps<VirtAddr> for AddressSpace<'a, B> {
    fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<usize, String> {
        let paddr = self.virt_to_phys(addr)?;
        self.backend.read_bytes(paddr, buf)
    }

    fn write_bytes(&self, addr: VirtAddr, buf: &[u8]) -> Result<usize, String> {
        let paddr = self.virt_to_phys(addr)?;
        self.backend.write_bytes(paddr, buf)
    }
}
