use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    host::KvmHandle,
    memory::{self, PAGE_SIZE},
    symbols::{SymbolStore, TypeInfo},
    types::*,
};
use indicatif::{ProgressBar, ProgressStyle};
use pelite::pe64::{Pe, PeView};
use zerocopy::IntoBytes;

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
) -> Result<Vec<u8>> {
    let mut header_buf = [0u8; 0x1000];

    memory.read_bytes(base_address, &mut header_buf)?;

    let view = PeView::from_bytes(&header_buf)?;
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

    pub fn read<T>(&self, kvm: &KvmHandle) -> Result<T>
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

    pub fn load_symbols(mut self, kvm: &KvmHandle, symbols: &mut SymbolStore) -> Result<Self> {
        self.guid = symbols.load_from_binary(kvm, &mut self)?;
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

    pub fn symbol<'a, S>(&'a self, symbols: &SymbolStore, name: S) -> Result<SymbolRef<'a>>
    where
        S: Into<String>,
    {
        let name = name.into();

        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        let rva = symbols
            .get_rva_of_symbol(guid, &name)
            .ok_or(Error::SymbolNotFound(name))?;
        Ok(SymbolRef { obj: self, rva })
    }

    pub fn closest_symbol(
        &self,
        symbols: &SymbolStore,
        address: VirtAddr,
    ) -> Result<(String, u32)> {
        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        let result = symbols
            .get_address_of_closest_symbol(guid, self.base_address, address)
            .ok_or(Error::UnknownAddress(address))?;
        Ok(result)
    }

    // TODO binary should probably be reread to ensure correctness
    // TODO bc shared memory might/isnt used, this needs to be mutable to ensure data is fresh :/
    pub fn view<B: MemoryOps<PhysAddr>>(&mut self, backend: &B) -> Option<PeView<'_>> {
        if self.binary_snapshot.is_empty() {
            let memory = self.memory(backend);
            self.binary_snapshot = read_pe_image(self.base_address, &memory).ok()?;
        }

        PeView::from_bytes(&self.binary_snapshot).ok()
    }

    pub fn try_get_struct<S>(&self, symbols: &SymbolStore, name: S) -> Result<TypeInfo>
    where
        S: Into<String> + AsRef<str>,
    {
        let guid = self.guid.ok_or(Error::ExpectedSymbols)?;
        let type_info = symbols
            .dump_struct_with_types(guid, name.as_ref())
            .ok_or(Error::StructNotFound(name.into()))?;
        Ok(type_info)
    }
}

pub struct Guest {
    pub ntoskrnl: WinObject,
}

pub struct Translation {
    #[allow(dead_code)]
    address: PhysAddr,
    #[allow(dead_code)]
    large: bool,
    writable: bool,
    user: bool,
    nx: bool,
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
            writable: pml4e.is_writable() && pdpte.is_writable() && pdpte.is_user(),
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

fn translate_virt2phys(kvm: &KvmHandle, dtb: Dtb, va: VirtAddr) -> Result<Option<Translation>> {
    let pml4e = kvm.read::<PageTableEntry>(dtb + va.pml4_index() as u64 * 8)?;
    if !pml4e.is_present() {
        return Ok(None);
    }

    let pdpte = kvm.read::<PageTableEntry>(pml4e.page_frame() + va.pdpt_index() as u64 * 8)?;
    if !pdpte.is_present() {
        return Ok(None);
    }

    if pdpte.is_large_page() {
        return Ok(Some(Translation::new_huge(pml4e, pdpte, va)));
    }

    let pde = kvm.read::<PageTableEntry>(pdpte.page_frame() + va.pd_index() as u64 * 8)?;
    if !pde.is_present() {
        return Ok(None);
    }

    if pde.is_large_page() {
        return Ok(Some(Translation::new_large(pml4e, pdpte, pde, va)));
    }

    let pte = kvm.read::<PageTableEntry>(pde.page_frame() + va.pt_index() as u64 * 8)?;
    if !pte.is_present() {
        return Ok(None);
    }

    Ok(Some(Translation::new(pml4e, pdpte, pde, pte, va)))
}

fn is_valid_kernel_dtb(kvm: &KvmHandle, dtb: Dtb) -> Result<bool> {
    let kernel_pml4 = kvm.read::<[PageTableEntry; 256]>(dtb + 8 * 256)?;

    if kernel_pml4
        .into_iter()
        .filter(|e| e.page_frame() == dtb)
        .count()
        != 1
    {
        return Ok(false);
    }

    // Check if use KUSER_SHARED_DATA is mapped
    const KUSER_SHARED_DATA_VA: VirtAddr = VirtAddr::from_u64(0xfffff78000000000);

    let Some(xlat) = translate_virt2phys(kvm, dtb, KUSER_SHARED_DATA_VA)? else {
        return Ok(false);
    };

    Ok(!xlat.writable && !xlat.user && xlat.nx)
}

fn find_kernel_dtb(kvm: &KvmHandle) -> Result<Option<Dtb>> {
    for dtb in (0x1000..0x1000000).step_by(PAGE_SIZE) {
        if is_valid_kernel_dtb(kvm, dtb)? {
            return Ok(Some(dtb));
        }
    }

    Ok(None)
}

fn find_ntoskrnl_va(kernel_dtb: Dtb, kvm: &KvmHandle) -> Result<Option<VirtAddr>> {
    const KERNEL_VA_MIN: VirtAddr = VirtAddr::from_u64(0xfffff80000000000);
    const KERNEL_VA_MAX: VirtAddr = VirtAddr::from_u64(0xfffff80800000000);

    let pml4e_count = KERNEL_VA_MAX.pml4_index() - KERNEL_VA_MIN.pml4_index() + 1;

    let kernel_pml4 = kvm.read::<[PageTableEntry; 512]>(kernel_dtb)?;
    for (pml4_index, pml4e) in kernel_pml4
        .into_iter()
        .enumerate()
        .skip(KERNEL_VA_MIN.pml4_index())
        .take(pml4e_count)
    {
        if !pml4e.is_present() {
            continue;
        }
        let pdpt = kvm.read::<[PageTableEntry; 512]>(pml4e.page_frame())?;

        let pdpte_count = if pml4_index == pml4e_count - 1 {
            KERNEL_VA_MAX.pdpt_index() + 1
        } else {
            512
        };

        for (pdpt_index, pdpte) in pdpt.into_iter().take(pdpte_count).enumerate() {
            if !pdpte.is_present() {
                continue;
            }

            if pdpte.is_large_page() {
                continue;
            }

            let pd = kvm.read::<[PageTableEntry; 512]>(pdpte.page_frame())?;

            let pde_count = if pdpt_index == pdpte_count - 1 {
                KERNEL_VA_MAX.pd_index() + 1
            } else {
                512
            };

            for (pd_index, pde) in pd.into_iter().take(pde_count).enumerate() {
                if !pde.is_present() {
                    continue;
                }

                if pde.is_large_page() {
                    continue;
                }

                let pt = kvm.read::<[PageTableEntry; 512]>(pde.page_frame())?;

                let pte_count = if pd_index == pde_count - 1 {
                    KERNEL_VA_MAX.pt_index() + 1
                } else {
                    512
                };

                for (pt_index, pte) in pt.into_iter().take(pte_count).enumerate() {
                    if !pte.is_present() {
                        continue;
                    }

                    if pte.is_writable() && !pte.is_user() && pte.is_nx() {
                        let phys = pte.page_frame();
                        let header = kvm.read::<[u8; 0x1000]>(phys)?;

                        if header[..4] != [0x4d, 0x5a, 0x90, 0x00] {
                            continue;
                        }

                        for chunk in header.chunks_exact(8) {
                            if chunk == b"POOLCODE" {
                                let va =
                                    VirtAddr::construct(pml4_index, pdpt_index, pd_index, pt_index);
                                return Ok(Some(va));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

fn find_ntoskrnl(kvm: &KvmHandle) -> Result<Option<WinObject>> {
    let Some(kernel_dtb) = find_kernel_dtb(kvm)? else {
        return Ok(None);
    };

    let Some(ntoskrnl_va) = find_ntoskrnl_va(kernel_dtb, kvm)? else {
        return Ok(None);
    };

    let ntoskrnl = WinObject::new(kernel_dtb, ntoskrnl_va);
    Ok(Some(ntoskrnl))
}

impl Guest {
    // TODO (everywhere) use MemoryOps, not KvmHandle...
    pub fn new(kvm: &KvmHandle, symbols: &mut SymbolStore) -> Result<Self> {
        let ntoskrnl = find_ntoskrnl(kvm)?
            .ok_or(Error::NtoskrnlNotFound)?
            .load_symbols(kvm, symbols)?;

        Ok(Self { ntoskrnl })
    }

    pub fn enumerate_processes(
        &self,
        kvm: &KvmHandle,
        symbols: &SymbolStore,
    ) -> Result<Vec<ProcessInfo>> {
        let memory = self.ntoskrnl.memory(kvm);

        let eprocess_info = self.ntoskrnl.try_get_struct(symbols, "_EPROCESS")?;
        let active_process_links_offset =
            eprocess_info.try_get_field_offset("ActiveProcessLinks")?;
        let pcb_offset = eprocess_info.try_get_field_offset("Pcb")?;

        let kprocess_info = self.ntoskrnl.try_get_struct(symbols, "_KPROCESS")?;
        let dir_table_base_offset =
            pcb_offset + kprocess_info.try_get_field_offset("DirectoryTableBase")?;
        let unique_process_id_offset = eprocess_info.try_get_field_offset("UniqueProcessId")?;
        let image_filename_offset = eprocess_info.try_get_field_offset("ImageFileName")?;
        let peb_offset = eprocess_info.try_get_field_offset("Peb")?;

        let peb_info = self.ntoskrnl.try_get_struct(symbols, "_PEB")?;
        let ldr_offset = peb_info.try_get_field_offset("Ldr")?;
        let image_base_address_offset = peb_info.try_get_field_offset("ImageBaseAddress")?;

        let ldr_info = self.ntoskrnl.try_get_struct(symbols, "_PEB_LDR_DATA")?;
        let in_load_order_offset = ldr_info.try_get_field_offset("InLoadOrderModuleList")?;

        let ldr_entry_info = self
            .ntoskrnl
            .try_get_struct(symbols, "_LDR_DATA_TABLE_ENTRY")?;
        let dll_base_offset = ldr_entry_info.try_get_field_offset("DllBase")?;
        let base_dll_name_offset = ldr_entry_info.try_get_field_offset("BaseDllName")?;

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

            let pid = memory.read::<u64>(current_eprocess + unique_process_id_offset)?;
            let dtb = memory.read::<Dtb>(current_eprocess + dir_table_base_offset)? & !0xfff;

            if dtb == 0 {
                break;
            }

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

            let flink = memory.read::<VirtAddr>(current_eprocess + active_process_links_offset)?;
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
    ) -> Result<String> {
        let kernel_memory = self.ntoskrnl.memory(kvm);
        let process_memory = memory::AddressSpace::new(kvm, dtb);

        let peb_addr: VirtAddr = kernel_memory.read(eprocess_va + peb_offset)?;
        if peb_addr.is_zero() {
            return Err(Error::MissingPEB);
        }

        let image_base: VirtAddr = process_memory.read(peb_addr + image_base_address_offset)?;
        if image_base.is_zero() {
            return Err(Error::MissingImageBase);
        }

        let ldr_addr: VirtAddr = process_memory.read(peb_addr + ldr_offset)?;
        if ldr_addr.is_zero() {
            return Err(Error::MissingLDR);
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
                    process_memory.read(entry_base + base_dll_name_offset + 8u32)?;

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

        Err(Error::MissingImage)
    }

    pub fn winobj_from_process_info(
        &self,
        kvm: &KvmHandle,
        symbols: &SymbolStore,
        info: &ProcessInfo,
    ) -> Result<WinObject> {
        let memory = memory::AddressSpace::new(kvm, info.dtb);

        let eprocess_info = self.ntoskrnl.try_get_struct(symbols, "_EPROCESS")?;
        let peb_offset = eprocess_info.try_get_field_offset("Peb")?;

        let peb_addr: VirtAddr = self
            .ntoskrnl
            .memory(kvm)
            .read(info.eprocess_va + peb_offset)?;

        if peb_addr.0 == 0 {
            return Err(Error::MissingPEB);
        }

        let peb_info = self.ntoskrnl.try_get_struct(symbols, "_PEB")?;
        let image_base_offset = peb_info.try_get_field_offset("ImageBaseAddress")?;

        let base_address: VirtAddr = memory.read(peb_addr + image_base_offset)?;

        Ok(WinObject::new(info.dtb, base_address))
    }

    pub fn get_process_modules(
        &self,
        kvm: &KvmHandle,
        symbols: &SymbolStore,
        info: &ProcessInfo,
    ) -> Result<Vec<ModuleInfo>> {
        let kernel_memory = self.ntoskrnl.memory(kvm);
        let process_memory = memory::AddressSpace::new(kvm, info.dtb);

        // Get PEB offset from _EPROCESS
        let eprocess_info = self.ntoskrnl.try_get_struct(symbols, "_EPROCESS")?;
        let peb_offset = eprocess_info.try_get_field_offset("Peb")?;

        let peb_addr: VirtAddr = kernel_memory.read(info.eprocess_va + peb_offset)?;
        if peb_addr.is_zero() {
            return Err(Error::MissingPEB);
        }

        let peb_info = self.ntoskrnl.try_get_struct(symbols, "_PEB")?;
        let ldr_offset = peb_info.try_get_field_offset("Ldr")?;

        let ldr_addr: VirtAddr = process_memory.read(peb_addr + ldr_offset)?;

        if ldr_addr.is_zero() {
            return Ok(Vec::new());
        }

        let ldr_info = self.ntoskrnl.try_get_struct(symbols, "_PEB_LDR_DATA")?;
        let in_load_order_offset = ldr_info.try_get_field_offset("InLoadOrderModuleList")?;

        let ldr_entry_info = self
            .ntoskrnl
            .try_get_struct(symbols, "_LDR_DATA_TABLE_ENTRY")?;
        let dll_base_offset = ldr_entry_info.try_get_field_offset("DllBase")?;
        let size_of_image_offset = ldr_entry_info.try_get_field_offset("SizeOfImage")?;
        let base_dll_name_offset = ldr_entry_info.try_get_field_offset("BaseDllName")?;

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
                process_memory.read(entry_base + base_dll_name_offset + 8u32)?;

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
    ) -> Result<Vec<ModuleInfo>> {
        let memory = self.ntoskrnl.memory(kvm);

        let ps_loaded_module_list = self
            .ntoskrnl
            .symbol(symbols, "PsLoadedModuleList")?
            .address();

        // Get _KLDR_DATA_TABLE_ENTRY field offsets (kernel uses KLDR variant)
        // Fall back to _LDR_DATA_TABLE_ENTRY if KLDR not found
        let ldr_entry_info = self
            .ntoskrnl
            .try_get_struct(symbols, "_KLDR_DATA_TABLE_ENTRY")
            .or_else(|_| {
                self.ntoskrnl
                    .try_get_struct(symbols, "_LDR_DATA_TABLE_ENTRY")
            })?;
        let dll_base_offset = ldr_entry_info.try_get_field_offset("DllBase")?;
        let size_of_image_offset = ldr_entry_info.try_get_field_offset("SizeOfImage")?;
        let base_dll_name_offset = ldr_entry_info.try_get_field_offset("BaseDllName")?;

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
            let name_buffer: VirtAddr = memory.read(entry_base + base_dll_name_offset + 8u32)?;

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
    ) -> Result<usize> {
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

            if let Ok(Some((job, guid))) =
                SymbolStore::extract_download_job(kvm, dtb, module.base_address)
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

            for (job, guid, module) in already_loaded.into_iter().chain(jobs_with_info.into_iter())
            {
                if symbols
                    .load_downloaded_pdb(
                        &job,
                        guid,
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
    ) -> Result<usize> {
        use crate::symbols::{DownloadJob, SymbolStore, download_pdbs_parallel};

        let modules = self.get_process_modules(kvm, symbols, info)?;
        let dtb = info.dtb;

        let mut jobs_with_info: Vec<(DownloadJob, u128, ModuleInfo)> = Vec::new();
        let mut already_loaded: Vec<(DownloadJob, u128, ModuleInfo)> = Vec::new();
        let mut loaded = 0;

        for module in &modules {
            if let Ok(Some((job, guid))) =
                SymbolStore::extract_download_job(kvm, dtb, module.base_address)
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
