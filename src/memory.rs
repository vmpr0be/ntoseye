use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::*;

// PageFrameNumber
pub const PFN_MASK: u64 = (!0xFu64 << 8) & 0xFFFFFFFFFu64;
pub const PAGE_SIZE: usize = 0x1000; // 4KiB
pub const PAGE_SHIFT: u32 = 12;
pub const PTE_SHIFT: u8 = 12;
pub const PDE_SHIFT: u8 = 21;
pub const PDPTE_SHIFT: u8 = 30;
pub const PML4E_SHIFT: u8 = 39;
pub const PT_INDEX_MASK: u64 = 0x1FF;

// 'a = lifetime of the borrow of the backend
//  B = any type that implements phys mem
pub struct AddressSpace<'a, B: MemoryOps<PhysAddr>> {
    backend: &'a B,
    dtb: Dtb,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PteLevel {
    Pte = 1,
    Pde,
    Pdpte,
    Pml4e,
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    pub fn new(backend: &'a B, dtb: Dtb) -> Self {
        Self { backend, dtb }
    }

    fn read_pt_entry(&self, table_base: PhysAddr, index: usize) -> Result<PageTableEntry> {
        self.backend.read(table_base + 8 * index as u64)
    }

    pub fn virt_to_phys(&self, vaddr: VirtAddr) -> Result<PhysAddr> {
        let pml4e = self.read_pt_entry(self.dtb, vaddr.pml4_index())?;
        if !pml4e.is_present() {
            return Err(Error::PTEntryNotPresent(PteLevel::Pml4e));
        }

        let pdpte = self.read_pt_entry(pml4e.page_frame(), vaddr.pdpt_index())?;
        if !pdpte.is_present() {
            return Err(Error::PTEntryNotPresent(PteLevel::Pdpte));
        }

        if pdpte.is_large_page() {
            return Ok(pdpte.page_frame() + vaddr.huge_page_offset());
        }

        let pde = self.read_pt_entry(pdpte.page_frame(), vaddr.pd_index())?;
        if !pde.is_present() {
            return Err(Error::PTEntryNotPresent(PteLevel::Pde));
        }

        if pde.is_large_page() {
            return Ok(pde.page_frame() + vaddr.large_page_offset());
        }

        let pte = self.read_pt_entry(pde.page_frame(), vaddr.pt_index())?;
        if !pte.is_present() {
            return Err(Error::PTEntryNotPresent(PteLevel::Pte));
        }

        Ok(pte.page_frame() + vaddr.page_offset())
    }
}

impl<'a, B: MemoryOps<PhysAddr>> MemoryOps<VirtAddr> for AddressSpace<'a, B> {
    fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<usize> {
        let paddr = self.virt_to_phys(addr)?;
        self.backend.read_bytes(paddr, buf)
    }

    fn write_bytes(&self, addr: VirtAddr, buf: &[u8]) -> Result<usize> {
        let paddr = self.virt_to_phys(addr)?;
        self.backend.write_bytes(paddr, buf)
    }
}
