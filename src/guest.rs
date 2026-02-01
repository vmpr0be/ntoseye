use crate::{
    backend::MemoryOps,
    host::KvmHandle,
    memory::{self},
    symbols::{SymbolStore, TypeInfo},
    types::*,
};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use pelite::pe64::{Pe, PeView};
use zerocopy::{FromBytes, IntoBytes};

/// used for enumeration without loading full WinObject
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u64,
    pub name: String,
    pub dtb: Dtb,
    pub eprocess_va: VirtAddr,
}

/// module metadata from PEB LDR list
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub short_name: String,
    pub base_address: VirtAddr,
    pub size: u32,
}

impl ModuleInfo {
    pub fn new(name: String, base_address: VirtAddr, size: u32) -> Self {
        let short_name = Self::derive_short_name(&name);
        Self {
            name,
            short_name,
            base_address,
            size,
        }
    }

    pub fn derive_short_name(name: &str) -> String {
        let filename = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let without_ext = filename
            .rsplit_once('.')
            .map(|(base, _)| base)
            .unwrap_or(filename);

        let lowered = without_ext.to_lowercase();
        match lowered.as_str() {
            "ntoskrnl" | "ntkrnlmp" | "ntkrnlpa" | "ntkrpamp" => "nt".to_string(),
            _ => lowered,
        }
    }
}

pub fn read_pe_image<'a, B: MemoryOps<PhysAddr>>(
    base_address: VirtAddr,
    memory: &memory::AddressSpace<'a, B>,
) -> Result<Vec<u8>, String> {
    let mut header_buf = [0u8; 0x1000];

    memory.read_bytes(base_address, &mut header_buf)?;

    let view = PeView::from_bytes(&header_buf).map_err(|e| format!("header parse error: {}", e))?;
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
    binary_snapshot: Vec<u8>,
    pub guid: Option<u128>,
}

impl WinObject {
    pub fn new(dtb: Dtb, base_address: VirtAddr) -> Self {
        Self {
            base_address,
            dtb,
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

    pub fn dtb(&self) -> Dtb {
        self.dtb
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

    pub fn closest_symbol(
        &self,
        symbols: &SymbolStore,
        address: VirtAddr,
    ) -> Result<(String, u32), String> {
        let guid = self.guid.ok_or("no guid found for binary")?;
        let result = symbols
            .get_address_of_closest_symbol(guid, self.base_address, address)
            .ok_or(format!("no symbol found near address `{:#x}`", address))?;
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

fn scan_small_pages(
    kvm: &KvmHandle,
    pa_table: u64,
    va_base: u64,
    va_min: u64,
    va_max: u64,
    level: usize,
    candidates: &mut std::collections::BTreeSet<u64>,
) {
    if level == 0 {
        return;
    }

    let page: [u8; 0x1000] = match kvm.read(PhysAddr(pa_table)) {
        Ok(page) => page,
        Err(_) => return,
    };

    let va_base = if level == 4 {
        if !verify_pml4(&page, pa_table) {
            return;
        }
        0
    } else {
        va_base
    };

    let ptes: &[PageTableEntry] = FromBytes::ref_from_bytes(&page).unwrap();

    for i in 0..512 {
        let va_current =
            memory::sign_extend_48bit(va_base + ((i as u64) << PML_REGION_SIZE[level]));

        if va_current < va_min {
            continue;
        }
        if va_current > va_max {
            return;
        }

        let pte = ptes[i];
        if !pte.is_present() {
            continue;
        }

        if level == 1 {
            // Look for the ntoskrnl small page pattern:
            // page i-1 is empty
            // page i is ACTIVE-WRITE-SUPERVISOR-NOEXECUTE 0x8000000000000003
            // pages i+1 to i+31 are ACTIVE-SUPERVISOR 0x01

            if i == 0 {
                continue;
            }
            if !ptes[i - 1].is_zero() {
                continue;
            }
            if (pte.0 & 0x800000000000000f) != 0x8000000000000003 {
                continue;
            }

            let mut valid = true;
            for j in (i + 2)..std::cmp::min(i + 32, 512) {
                if (ptes[j].0 & 0x0f) != 0x01 {
                    valid = false;
                    break;
                }
            }

            if valid {
                candidates.insert(va_current);
            }
            continue;
        }

        if pte.is_large_page() {
            continue;
        }

        let next_table = pte.pte_frame_addr();
        scan_small_pages(kvm, next_table, va_current, va_min, va_max, level - 1, candidates);
    }
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
                            ));
                        }
                    }
                }
            }
        }

        let mut candidates = std::collections::BTreeSet::new();
        scan_small_pages(kvm, pa_dtb, 0, KERNEL_VA_MIN, KERNEL_VA_MAX, 4, &mut candidates);

        for va in candidates {
            let mut page_buf = [0u8; 0x1000];
            if kernel_space.read_bytes(VirtAddr(va), &mut page_buf).is_err() {
                continue;
            }

            // MZ
            let header = u16::read_from_bytes(&page_buf[0..2]).unwrap();
            if header != 0x5a4d {
                continue;
            }

            // POOLCODE signature
            for o in (0usize..0x1000).step_by(8) {
                let poolcode = u64::read_from_bytes(&page_buf[o..o + 8]).unwrap();
                if poolcode == 0x45444F434C4F4F50u64 {
                    return Ok(WinObject::new(Dtb(PhysAddr(pa_dtb)), VirtAddr(va)));
                }
            }
        }

        break;
    }

    Err("failed to find ntoskrnl base address".into())
}

impl Guest {
    // TODO (everywhere) use MemoryOps, not KvmHandle...
    pub fn new(kvm: &KvmHandle, symbols: &mut SymbolStore) -> Result<Self, String> {
        let ntoskrnl = get_ntoskrnl_winobj(kvm)?.load_symbols(kvm, symbols)?;
        Ok(Self { ntoskrnl })
    }

    pub fn enumerate_processes(
        &self,
        kvm: &KvmHandle,
        symbols: &SymbolStore,
    ) -> Result<Vec<ProcessInfo>, String> {
        let memory = self.ntoskrnl.memory(kvm);

        let eprocess_info = self
            .ntoskrnl
            .class(symbols, "_EPROCESS")
            .map_err(|_| "failed to get _EPROCESS type info")?;

        let active_process_links_offset = eprocess_info
            .fields
            .get("ActiveProcessLinks")
            .ok_or("ActiveProcessLinks field not found")?
            .offset as u64;

        let pcb_offset = eprocess_info
            .fields
            .get("Pcb")
            .ok_or("Pcb field not found")?
            .offset as u64;

        let kprocess_info = self
            .ntoskrnl
            .class(symbols, "_KPROCESS")
            .map_err(|_| "failed to get _KPROCESS type info")?;

        let dir_table_base_offset = pcb_offset
            + kprocess_info
                .fields
                .get("DirectoryTableBase")
                .ok_or("DirectoryTableBase field not found in _KPROCESS")?
                .offset as u64;

        let unique_process_id_offset = eprocess_info
            .fields
            .get("UniqueProcessId")
            .ok_or("UniqueProcessId field not found")?
            .offset as u64;

        let image_filename_offset = eprocess_info
            .fields
            .get("ImageFileName")
            .ok_or("ImageFileName field not found")?
            .offset as u64;

        let peb_offset = eprocess_info
            .fields
            .get("Peb")
            .ok_or("Peb field not found")?
            .offset as u64;

        let peb_info = self
            .ntoskrnl
            .class(symbols, "_PEB")
            .map_err(|_| "failed to get _PEB type info")?;

        let ldr_offset = peb_info
            .fields
            .get("Ldr")
            .ok_or("Ldr field not found")?
            .offset as u64;

        let image_base_address_offset = peb_info
            .fields
            .get("ImageBaseAddress")
            .ok_or("ImageBaseAddress field not found")?
            .offset as u64;

        let ldr_info = self
            .ntoskrnl
            .class(symbols, "_PEB_LDR_DATA")
            .map_err(|_| "failed to get _PEB_LDR_DATA type info")?;

        let in_load_order_offset = ldr_info
            .fields
            .get("InLoadOrderModuleList")
            .ok_or("InLoadOrderModuleList field not found")?
            .offset as u64;

        let ldr_entry_info = self
            .ntoskrnl
            .class(symbols, "_LDR_DATA_TABLE_ENTRY")
            .map_err(|_| "failed to get _LDR_DATA_TABLE_ENTRY type info")?;

        let dll_base_offset = ldr_entry_info
            .fields
            .get("DllBase")
            .ok_or("DllBase field not found")?
            .offset as u64;

        let base_dll_name_offset = ldr_entry_info
            .fields
            .get("BaseDllName")
            .ok_or("BaseDllName field not found")?
            .offset as u64;

        let ps_initial_system_process: VirtAddr = self
            .ntoskrnl
            .symbol(symbols, "PsInitialSystemProcess")?
            .read(kvm)?;

        let mut processes = Vec::new();
        let mut visited = std::collections::HashSet::new();

        let mut current_eprocess = ps_initial_system_process;

        loop {
            if current_eprocess.0 == 0 || visited.contains(&current_eprocess.0) {
                break;
            }
            visited.insert(current_eprocess.0);

            let pid: u64 = memory.read(current_eprocess + unique_process_id_offset)?;
            let dtb: u64 = memory.read(current_eprocess + dir_table_base_offset)?;

            if dtb == 0 {
                break;
            }

            let dtb = Dtb(PhysAddr(dtb));

            let name = self
                .get_full_process_name(
                    kvm,
                    current_eprocess,
                    dtb,
                    peb_offset,
                    ldr_offset,
                    image_base_address_offset,
                    in_load_order_offset,
                    dll_base_offset,
                    base_dll_name_offset,
                )
                .unwrap_or_else(|_| {
                    let mut name_buf = [0u8; 15];
                    if memory
                        .read_bytes(current_eprocess + image_filename_offset, &mut name_buf)
                        .is_ok()
                    {
                        String::from_utf8_lossy(
                            &name_buf[..name_buf.iter().position(|&c| c == 0).unwrap_or(15)],
                        )
                        .to_string()
                    } else {
                        "<unknown>".to_string()
                    }
                });

            processes.push(ProcessInfo {
                pid,
                name,
                dtb,
                eprocess_va: current_eprocess,
            });

            let flink: VirtAddr = memory.read(current_eprocess + active_process_links_offset)?;
            if flink.0 == 0 {
                break;
            }

            current_eprocess = flink - active_process_links_offset;
            if current_eprocess == ps_initial_system_process {
                break;
            }
        }

        Ok(processes)
    }

    #[allow(clippy::too_many_arguments)]
    fn get_full_process_name(
        &self,
        kvm: &KvmHandle,
        eprocess_va: VirtAddr,
        dtb: Dtb,
        peb_offset: u64,
        ldr_offset: u64,
        image_base_address_offset: u64,
        in_load_order_offset: u64,
        dll_base_offset: u64,
        base_dll_name_offset: u64,
    ) -> Result<String, String> {
        let kernel_memory = self.ntoskrnl.memory(kvm);
        let process_memory = memory::AddressSpace::new(kvm, dtb);

        let peb_addr: VirtAddr = kernel_memory.read(eprocess_va + peb_offset)?;
        if peb_addr.0 == 0 {
            return Err("no PEB".into());
        }

        let image_base: VirtAddr = process_memory.read(peb_addr + image_base_address_offset)?;
        if image_base.0 == 0 {
            return Err("no ImageBaseAddress".into());
        }

        let ldr_addr: VirtAddr = process_memory.read(peb_addr + ldr_offset)?;
        if ldr_addr.0 == 0 {
            return Err("no Ldr".into());
        }

        let list_head: VirtAddr = process_memory.read(ldr_addr + in_load_order_offset)?;
        let list_end = ldr_addr + in_load_order_offset;

        let mut current = list_head;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        while current.0 != 0 && current != list_end && iterations < MAX_ITERATIONS {
            iterations += 1;

            let entry_base = current;
            let dll_base: VirtAddr = process_memory.read(entry_base + dll_base_offset)?;

            if dll_base == image_base {
                // Read UNICODE_STRING for BaseDllName
                let name_length: u16 = process_memory.read(entry_base + base_dll_name_offset)?;
                let name_buffer: VirtAddr =
                    process_memory.read(entry_base + base_dll_name_offset + 8)?;

                if name_length > 0 && name_buffer.0 != 0 && name_length < 520 {
                    let mut name_buf = vec![0u8; name_length as usize];
                    process_memory.read_bytes(name_buffer, &mut name_buf)?;

                    // Convert UTF-16LE to String
                    let u16_chars: Vec<u16> = name_buf
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    return Ok(String::from_utf16_lossy(&u16_chars));
                }
            }

            let next: VirtAddr = process_memory.read(current)?;
            if next == current {
                break;
            }
            current = next;
        }

        Err("main module not found in LDR list".into())
    }

    pub fn winobj_from_process_info(
        &self,
        kvm: &KvmHandle,
        symbols: &SymbolStore,
        info: &ProcessInfo,
    ) -> Result<WinObject, String> {
        let memory = memory::AddressSpace::new(kvm, info.dtb);

        let eprocess_info = self
            .ntoskrnl
            .class(symbols, "_EPROCESS")
            .map_err(|_| "failed to get _EPROCESS type info")?;

        let peb_offset = eprocess_info
            .fields
            .get("Peb")
            .ok_or("Peb field not found")?
            .offset as u64;

        let peb_addr: VirtAddr = self
            .ntoskrnl
            .memory(kvm)
            .read(info.eprocess_va + peb_offset)?;

        if peb_addr.0 == 0 {
            return Err("process has no PEB (kernel process?)".into());
        }

        let peb_info = self
            .ntoskrnl
            .class(symbols, "_PEB")
            .map_err(|_| "failed to get _PEB type info")?;

        let image_base_offset = peb_info
            .fields
            .get("ImageBaseAddress")
            .ok_or("ImageBaseAddress field not found")?
            .offset as u64;

        let base_address: VirtAddr = memory.read(peb_addr + image_base_offset)?;

        Ok(WinObject::new(info.dtb, base_address))
    }

    pub fn get_process_modules(
        &self,
        kvm: &KvmHandle,
        symbols: &SymbolStore,
        info: &ProcessInfo,
    ) -> Result<Vec<ModuleInfo>, String> {
        let kernel_memory = self.ntoskrnl.memory(kvm);
        let process_memory = memory::AddressSpace::new(kvm, info.dtb);

        // Get PEB offset from _EPROCESS
        let eprocess_info = self
            .ntoskrnl
            .class(symbols, "_EPROCESS")
            .map_err(|_| "failed to get _EPROCESS type info")?;

        let peb_offset = eprocess_info
            .fields
            .get("Peb")
            .ok_or("Peb field not found")?
            .offset as u64;

        let peb_addr: VirtAddr = kernel_memory.read(info.eprocess_va + peb_offset)?;
        if peb_addr.0 == 0 {
            return Err("process has no PEB (kernel process?)".into());
        }

        let peb_info = self
            .ntoskrnl
            .class(symbols, "_PEB")
            .map_err(|_| "failed to get _PEB type info")?;

        let ldr_offset = peb_info
            .fields
            .get("Ldr")
            .ok_or("Ldr field not found")?
            .offset as u64;

        let ldr_addr: VirtAddr = process_memory.read(peb_addr + ldr_offset)?;

        if ldr_addr.0 == 0 {
            return Ok(Vec::new());
        }

        let ldr_info = self
            .ntoskrnl
            .class(symbols, "_PEB_LDR_DATA")
            .map_err(|_| "failed to get _PEB_LDR_DATA type info")?;

        let in_load_order_offset = ldr_info
            .fields
            .get("InLoadOrderModuleList")
            .ok_or("InLoadOrderModuleList field not found")?
            .offset as u64;

        let ldr_entry_info = self
            .ntoskrnl
            .class(symbols, "_LDR_DATA_TABLE_ENTRY")
            .map_err(|_| "failed to get _LDR_DATA_TABLE_ENTRY type info")?;

        let dll_base_offset = ldr_entry_info
            .fields
            .get("DllBase")
            .ok_or("DllBase field not found")?
            .offset as u64;

        let size_of_image_offset = ldr_entry_info
            .fields
            .get("SizeOfImage")
            .ok_or("SizeOfImage field not found")?
            .offset as u64;

        let base_dll_name_offset = ldr_entry_info
            .fields
            .get("BaseDllName")
            .ok_or("BaseDllName field not found")?
            .offset as u64;

        let list_head: VirtAddr = process_memory.read(ldr_addr + in_load_order_offset)?;
        let list_end = ldr_addr + in_load_order_offset;

        let mut modules = Vec::new();
        let mut current = list_head;

        loop {
            if current.0 == 0 || current == list_end {
                break;
            }

            // current points to InLoadOrderLinks, which is at offset 0 in LDR_DATA_TABLE_ENTRY
            let entry_base = current;

            let dll_base: VirtAddr = process_memory.read(entry_base + dll_base_offset)?;
            let size_of_image: u32 = process_memory.read(entry_base + size_of_image_offset)?;

            // Read UNICODE_STRING for BaseDllName
            let name_length: u16 = process_memory.read(entry_base + base_dll_name_offset)?;
            let name_buffer: VirtAddr =
                process_memory.read(entry_base + base_dll_name_offset + 8)?;

            let name = if name_length > 0 && name_buffer.0 != 0 {
                let mut name_buf = vec![0u8; name_length as usize];
                if process_memory
                    .read_bytes(name_buffer, &mut name_buf)
                    .is_ok()
                {
                    // Convert UTF-16LE to String
                    let u16_chars: Vec<u16> = name_buf
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&u16_chars)
                } else {
                    "<unknown>".to_string()
                }
            } else {
                "<unknown>".to_string()
            };

            if dll_base.0 != 0 {
                modules.push(ModuleInfo::new(name, dll_base, size_of_image));
            }

            let next: VirtAddr = process_memory.read(current)?;
            if next == current {
                break;
            }
            current = next;
        }

        Ok(modules)
    }

    pub fn get_kernel_modules(
        &self,
        kvm: &KvmHandle,
        symbols: &SymbolStore,
    ) -> Result<Vec<ModuleInfo>, String> {
        let memory = self.ntoskrnl.memory(kvm);

        let ps_loaded_module_list = self
            .ntoskrnl
            .symbol(symbols, "PsLoadedModuleList")?
            .address();

        // Get _KLDR_DATA_TABLE_ENTRY field offsets (kernel uses KLDR variant)
        // Fall back to _LDR_DATA_TABLE_ENTRY if KLDR not found
        let ldr_entry_info = self
            .ntoskrnl
            .class(symbols, "_KLDR_DATA_TABLE_ENTRY")
            .or_else(|_| self.ntoskrnl.class(symbols, "_LDR_DATA_TABLE_ENTRY"))
            .map_err(|_| "failed to get LDR entry type info")?;

        let dll_base_offset = ldr_entry_info
            .fields
            .get("DllBase")
            .ok_or("DllBase field not found")?
            .offset as u64;

        let size_of_image_offset = ldr_entry_info
            .fields
            .get("SizeOfImage")
            .ok_or("SizeOfImage field not found")?
            .offset as u64;

        let base_dll_name_offset = ldr_entry_info
            .fields
            .get("BaseDllName")
            .ok_or("BaseDllName field not found")?
            .offset as u64;

        let list_head: VirtAddr = memory.read(ps_loaded_module_list)?;
        let list_end = ps_loaded_module_list;

        let mut modules = Vec::new();
        let mut current = list_head;

        loop {
            if current.0 == 0 || current == list_end {
                break;
            }

            // current points to InLoadOrderLinks, which is at offset 0
            let entry_base = current;
            let dll_base: VirtAddr = memory.read(entry_base + dll_base_offset)?;
            let size_of_image: u32 = memory.read(entry_base + size_of_image_offset)?;

            // Read UNICODE_STRING for BaseDllName
            let name_length: u16 = memory.read(entry_base + base_dll_name_offset)?;
            let name_buffer: VirtAddr = memory.read(entry_base + base_dll_name_offset + 8)?;

            let name = if name_length > 0 && name_buffer.0 != 0 {
                let mut name_buf = vec![0u8; name_length as usize];
                if memory.read_bytes(name_buffer, &mut name_buf).is_ok() {
                    let u16_chars: Vec<u16> = name_buf
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&u16_chars)
                } else {
                    "<unknown>".to_string()
                }
            } else {
                "<unknown>".to_string()
            };

            if dll_base.0 != 0 {
                modules.push(ModuleInfo::new(name, dll_base, size_of_image));
            }

            let next: VirtAddr = memory.read(current)?;
            if next == current {
                break;
            }
            current = next;
        }

        Ok(modules)
    }

    fn is_session_space(addr: VirtAddr) -> bool {
        let prefix = addr.0 >> 44;
        prefix == 0xFFFF8 || prefix == 0xFFFF9 || prefix == 0xFFFFA
    }

    pub fn load_all_kernel_module_symbols(
        &self,
        kvm: &KvmHandle,
        symbols: &mut SymbolStore,
    ) -> Result<usize, String> {
        use crate::symbols::{DownloadJob, SymbolStore, download_pdbs_parallel};

        let modules = self.get_kernel_modules(kvm, symbols)?;
        let dtb = self.ntoskrnl.dtb;

        let mut jobs_with_info: Vec<(DownloadJob, u128, ModuleInfo)> = Vec::new();
        let mut already_loaded: Vec<(DownloadJob, u128, ModuleInfo)> = Vec::new();
        let mut loaded = 0;

        for module in &modules {
            if Self::is_session_space(module.base_address) {
                continue;
            }

            if let Ok((job, guid)) =
                SymbolStore::extract_download_job(kvm, dtb, module.base_address, &module.name)
            {
                if symbols.has_guid(guid) {
                    already_loaded.push((job, guid, module.clone()));
                    continue;
                }
                jobs_with_info.push((job, guid, module.clone()));
            }
        }

        let jobs: Vec<DownloadJob> = jobs_with_info.iter().map(|(j, _, _)| j.clone()).collect();
        let _ = download_pdbs_parallel(jobs);

        let total = already_loaded.len() + jobs_with_info.len();
        if total > 0 {
            let pb = ProgressBar::new(total as u64);
            pb.set_style(
                ProgressStyle::with_template("Indexing [{bar:40}] {pos}/{len}")
                    .unwrap()
                    .progress_chars("#-"),
            );

            for (job, guid, module) in already_loaded.iter().chain(jobs_with_info.iter()) {
                if symbols
                    .load_downloaded_pdb(
                        job,
                        *guid,
                        &module.name,
                        module.base_address,
                        module.size,
                        dtb,
                    )
                    .is_ok()
                {
                    loaded += 1;
                }
                pb.inc(1);
            }

            pb.finish_and_clear();
        }

        Ok(loaded)
    }

    pub fn load_all_process_module_symbols(
        &self,
        kvm: &KvmHandle,
        symbols: &mut SymbolStore,
        info: &ProcessInfo,
    ) -> Result<usize, String> {
        use crate::symbols::{DownloadJob, SymbolStore, download_pdbs_parallel};

        let modules = self.get_process_modules(kvm, symbols, info)?;
        let dtb = info.dtb;

        let mut jobs_with_info: Vec<(DownloadJob, u128, ModuleInfo)> = Vec::new();
        let mut already_loaded: Vec<(DownloadJob, u128, ModuleInfo)> = Vec::new();
        let mut loaded = 0;

        for module in &modules {
            if let Ok((job, guid)) =
                SymbolStore::extract_download_job(kvm, dtb, module.base_address, &module.name)
            {
                if symbols.has_guid(guid) {
                    already_loaded.push((job, guid, module.clone()));
                    continue;
                }
                jobs_with_info.push((job, guid, module.clone()));
            }
        }

        let jobs: Vec<DownloadJob> = jobs_with_info.iter().map(|(j, _, _)| j.clone()).collect();
        let _ = download_pdbs_parallel(jobs);

        let total = already_loaded.len() + jobs_with_info.len();
        if total > 0 {
            let pb = ProgressBar::new(total as u64);
            pb.set_style(
                ProgressStyle::with_template("Indexing [{bar:40}] {pos}/{len}")
                    .unwrap()
                    .progress_chars("#-"),
            );

            for (job, guid, module) in already_loaded.iter().chain(jobs_with_info.iter()) {
                if symbols
                    .load_downloaded_pdb(
                        job,
                        *guid,
                        &module.name,
                        module.base_address,
                        module.size,
                        dtb,
                    )
                    .is_ok()
                {
                    loaded += 1;
                }
                pb.inc(1);
            }

            pb.finish_and_clear();
        }

        Ok(loaded)
    }
}
