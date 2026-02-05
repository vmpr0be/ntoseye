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

pub struct Translation {
    #[allow(dead_code)]
    pub address: PhysAddr,
    #[allow(dead_code)]
    pub large: bool,
    pub writable: bool,
    pub user: bool,
    pub nx: bool,
}

impl Translation {
    pub const fn new_huge(pml4e: PageTableEntry, pdpte: PageTableEntry, va: VirtAddr) -> Self {
        Self {
            address: pdpte.page_frame() + va.huge_page_offset(),
            large: true,
            writable: pml4e.is_writable() && pdpte.is_writable(),
            user: pml4e.is_user() && pdpte.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx(),
        }
    }

    pub const fn new_large(
        pml4e: PageTableEntry,
        pdpte: PageTableEntry,
        pde: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        Self {
            address: pde.page_frame() + va.large_page_offset(),
            large: true,
            writable: pml4e.is_writable() && pdpte.is_writable() && pdpte.is_writable(),
            user: pml4e.is_user() && pdpte.is_user() && pde.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx() || pde.is_nx(),
        }
    }

    pub const fn new(
        pml4e: PageTableEntry,
        pdpte: PageTableEntry,
        pde: PageTableEntry,
        pte: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        Self {
            address: pte.page_frame() + va.page_offset(),
            large: false,
            writable: pml4e.is_writable()
                && pdpte.is_writable()
                && pde.is_writable()
                && pte.is_writable(),
            user: pml4e.is_user() && pdpte.is_user() && pde.is_user() && pte.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx() || pde.is_nx() || pte.is_nx(),
        }
    }
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    pub fn new(backend: &'a B, dtb: Dtb) -> Self {
        Self { backend, dtb }
    }

    fn read_pt_entry(&self, table_base: PhysAddr, index: usize) -> Result<PageTableEntry> {
        self.backend.read(table_base + 8 * index as u64)
    }

    pub fn virt_to_phys(&self, va: VirtAddr) -> Result<Option<Translation>> {
        let pml4e = self.read_pt_entry(self.dtb, va.pml4_index())?;
        if !pml4e.is_present() {
            return Ok(None);
        }

        let pdpte = self.read_pt_entry(pml4e.page_frame(), va.pdpt_index())?;
        if !pdpte.is_present() {
            return Ok(None);
        }

        if pdpte.is_large_page() {
            return Ok(Some(Translation::new_huge(pml4e, pdpte, va)));
        }

        let pde = self.read_pt_entry(pdpte.page_frame(), va.pd_index())?;
        if !pde.is_present() {
            return Ok(None);
        }

        if pde.is_large_page() {
            return Ok(Some(Translation::new_large(pml4e, pdpte, pde, va)));
        }

        let pte = self.read_pt_entry(pde.page_frame(), va.pt_index())?;
        if !pte.is_present() {
            return Ok(None);
        }

        Ok(Some(Translation::new(pml4e, pdpte, pde, pte, va)))
    }
}

impl<'a, B: MemoryOps<PhysAddr>> MemoryOps<VirtAddr> for AddressSpace<'a, B> {
    fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let xlat = self
            .virt_to_phys(addr)?
            .ok_or(Error::BadVirtualAddress(addr))?;

        self.backend.read_bytes(xlat.address, buf)
    }

    fn write_bytes(&self, addr: VirtAddr, buf: &[u8]) -> Result<()> {
        let xlat = self
            .virt_to_phys(addr)?
            .ok_or(Error::BadVirtualAddress(addr))?;

        self.backend.write_bytes(xlat.address, buf)
    }
}
