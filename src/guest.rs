use crate::{
    backend::MemoryOps,
    host::KvmHandle,
    memory::{self},
    symbols::{SymbolStore, TypeInfo},
    types::*,
};
use zerocopy::{FromBytes, IntoBytes};
use pelite::pe64::{Pe, PeView};
use anyhow::Result;

pub fn read_pe_image<'a, B: MemoryOps<PhysAddr>>(
    base_address: VirtAddr,
    memory: &memory::AddressSpace<'a, B>,
) -> Result<Vec<u8>, String> {
    let mut header_buf = [0u8; 0x1000];

    memory.read_bytes(base_address, &mut header_buf)?;

    let view = PeView::from_bytes(&header_buf).map_err(|e| format!("Header parse error: {}", e))?;
    let optional_header = view.optional_header();
    let sections = view.section_headers();

    let total_size = optional_header.SizeOfImage as usize;
    let mut image_buffer = vec![0u8; total_size];

    let header_len = std::cmp::min(header_buf.len(), total_size);
    image_buffer[..header_len].copy_from_slice(&header_buf[..header_len]);

    for section in sections {
        let v_addr = section.VirtualAddress as usize;
        let v_size = section.VirtualSize as usize;

        if v_addr + v_size > total_size {
            continue;
        }

        let read_addr = VirtAddr(base_address.0 + v_addr as u64);
        let target_slice = &mut image_buffer[v_addr..v_addr + v_size];

        let _ = memory.read_bytes(read_addr, target_slice);
    }

    Ok(image_buffer)
}

pub enum WinObjectKind {
    Ntoskrnl,
    KernelModule,
    Process,
    ProcessModule,
}

pub struct SymbolRef<'a> {
    obj: &'a WinObject,
    rva: u32,
}

impl SymbolRef<'_> {
    pub fn address(&self) -> VirtAddr {
        self.obj.address_of(self.rva)
    }

    pub fn read<T>(&self, kvm: &KvmHandle) -> Result<T, String>
    where
        T: IntoBytes + zerocopy::FromBytes + std::marker::Copy,
    {
        let memory = self.obj.memory(kvm);
        memory.read(self.address())
    }
}

pub struct WinObject {
    pub base_address: VirtAddr,
    dtb: Dtb,
    kind: WinObjectKind,
    binary_snapshot: Vec<u8>,
    pub guid: Option<u128>,
}

impl WinObject {
    pub fn new(dtb: Dtb, base_address: VirtAddr, kind: WinObjectKind) -> Self {
        Self {
            base_address,
            dtb,
            kind,
            binary_snapshot: Vec::new(),
            guid: None,
        }
    }

    pub fn load_symbols(
        mut self,
        kvm: &KvmHandle,
        symbols: &mut SymbolStore,
    ) -> Result<Self, String> {
        self.guid = Some(symbols.load_from_binary(kvm, &mut self)?);
        Ok(self)
    }

    pub fn address_of(&self, rva: impl Into<u64>) -> VirtAddr {
        self.base_address + rva.into()
    }

    pub fn memory<'a, B: MemoryOps<PhysAddr>>(
        &self,
        backend: &'a B,
    ) -> memory::AddressSpace<'a, B> {
        memory::AddressSpace::new(backend, self.dtb)
    }

    pub fn symbol<'a>(
        &'a self,
        symbols: &SymbolStore,
        name: &str,
    ) -> Result<SymbolRef<'a>, String> {
        let guid = self.guid.ok_or("no guid found for binary")?;
        let rva = symbols
            .get_rva_of_symbol(guid, name)
            .ok_or(format!("symbol `{}` not found", name))?;
        Ok(SymbolRef { obj: self, rva })
    }

    pub fn closest_symbol(&self, symbols: &SymbolStore, address: VirtAddr) -> Result<(String, u32), String> {
        let guid = self.guid.ok_or("no guid found for binary")?;
        let result = symbols.get_address_of_closest_symbol(guid, self.base_address, address).ok_or(format!("no symbol found near address `{:#x}`", address))?;
        Ok(result)
    }

    // TODO binary should probably be reread to ensure correctness
    // TODO bc shared memory might/isnt used, this needs to be mutable to ensure data is fresh :/
    pub fn view<'a, B: MemoryOps<PhysAddr>>(&mut self, backend: &'a B) -> Option<PeView<'_>> {
        if self.binary_snapshot.is_empty() {
            let memory = self.memory(backend);
            self.binary_snapshot = read_pe_image(self.base_address, &memory).ok()?;
        }

        PeView::from_bytes(&self.binary_snapshot).ok()
    }

    pub fn class(&self, symbols: &SymbolStore, name: &str) -> Result<TypeInfo, String> {
        let guid = self.guid.ok_or("no guid found for binary")?;
        let type_info = symbols
            .dump_struct_with_types(guid, name)
            .ok_or("failed to find structure")?;
        Ok(type_info)
    }
}

pub struct Guest {
    pub ntoskrnl: WinObject,
}

fn verify_pml4(page: &[u8; 0x1000], pa: u64) -> bool {
    let ptes: &[PageTableEntry] = FromBytes::ref_from_bytes(page).unwrap();

    // usermode PTEs
    let user_zero = ptes.iter().take(256).filter(|&&x| x.is_zero()).count();

    // kernelmode PTEs
    let (mut kernel_zero, mut kernel_valid, mut self_ref) = (0, 0, false);
    for &pte in &ptes[256..512] {
        if pte.is_zero() {
            kernel_zero += 1;
            continue;
        }

        // supervisor entry
        if pte.is_kernel_table() {
            let pdpt_pa = pte.pte_frame_addr();
            if pdpt_pa < 0x10000000000 {
                kernel_valid += 1;
            }
        }

        self_ref |= pte.is_self_ref(pa);
    }

    self_ref && kernel_valid >= 6 && user_zero > 0x40 && kernel_zero > 0x40
}

const PML_REGION_SIZE: [u64; 5] = [0, 12, 21, 30, 39];

// TODO i dont think u64 should be used here
fn scan_large_pages(
    kvm: &KvmHandle,
    pa_table: u64,
    va_base: u64,
    va_min: u64,
    va_max: u64,
    level: usize,
    out_va_base: &mut u64,
    out_size: &mut u64,
) -> bool {
    if level < 2 {
        return false;
    }

    let page: [u8; 0x1000] = match kvm.read(PhysAddr(pa_table)) {
        Ok(page) => page,
        Err(_) => return false,
    };

    if level == 4 {
        if !verify_pml4(&page, pa_table) {
            return false;
        }
    }

    let ptes: &[PageTableEntry] = FromBytes::ref_from_bytes(&page).unwrap();

    for (i, pte) in ptes.iter().enumerate() {
        let va_current = memory::sign_extend_48bit((i << PML_REGION_SIZE[level]) as u64 + va_base);

        if *out_va_base != 0 && (va_current > (*out_va_base + *out_size)) {
            return *out_size > 0;
        }

        if va_current < va_min {
            continue;
        }

        if va_current > va_max {
            return *out_size > 0;
        }

        if !pte.is_present() {
            continue;
        }

        if level == 2 {
            if !pte.is_large_page() {
                continue;
            }

            if *out_va_base == 0 {
                *out_va_base = va_current;
            }

            *out_size += 0x200000; // 2 MiB
        }

        if pte.is_large_page() {
            continue;
        }

        let next_table = pte.pte_frame_addr();
        if scan_large_pages(
            kvm,
            next_table,
            va_current,
            va_min,
            va_max,
            level - 1,
            out_va_base,
            out_size,
        ) {
            return true;
        }
    }

    false
}

fn get_ntoskrnl_winobj(kvm: &KvmHandle) -> Result<WinObject, String> {
    const KERNEL_VA_MIN: u64 = 0xfffff80000000000;
    const KERNEL_VA_MAX: u64 = 0xfffff807ffffffff;

    for pa_dtb in (0x1000u64..0x1000000).step_by(0x1000) {
        let page: [u8; 0x1000] = match kvm.read(PhysAddr(pa_dtb)) {
            Ok(page) => page,
            Err(_) => continue,
        };

        if !verify_pml4(&page, pa_dtb) {
            continue;
        }

        let mut kernel_base = 0u64;
        let mut kernel_size = 0u64;

        let kernel_space = memory::AddressSpace::new(kvm, Dtb(PhysAddr(pa_dtb)));

        if scan_large_pages(
            &kvm,
            pa_dtb,
            0,
            KERNEL_VA_MIN,
            KERNEL_VA_MAX,
            4,
            &mut kernel_base,
            &mut kernel_size,
        ) {
            if kernel_size >= 0x400000 && kernel_size < 0x1800000 {
                let mut kernel = vec![0u8; kernel_size as usize];

                if let Err(_) = kernel_space.read_bytes(VirtAddr(kernel_base), &mut kernel) {
                    continue;
                }

                for p in (0usize..kernel_size as usize).step_by(0x1000) {
                    let header = u16::read_from_bytes(&kernel[p..p + 2]).unwrap();
                    if header != 0x5a4d {
                        // MZ
                        continue;
                    }

                    for o in (0usize..0x1000).step_by(8) {
                        let poolcode = u64::read_from_bytes(&kernel[(p + o)..(p + o + 8)]).unwrap();
                        if poolcode == 0x45444F434C4F4F50u64 {
                            return Ok(WinObject::new(
                                Dtb(PhysAddr(pa_dtb)),
                                VirtAddr(kernel_base + p as u64),
                                WinObjectKind::Ntoskrnl,
                            ));
                        }
                    }
                }
            }
        }

        break;
    }

    // TODO implement small page walking?
    Err("failed to find ntoskrnl base address".into())
}

impl Guest {
    // TODO (everywhere) use MemoryOps, not KvmHandle...
    pub fn new(kvm: &KvmHandle, symbols: &mut SymbolStore) -> Result<Self, String> {
        let ntoskrnl = get_ntoskrnl_winobj(kvm)?.load_symbols(kvm, symbols)?;
        Ok(Self { ntoskrnl })
    }
}
