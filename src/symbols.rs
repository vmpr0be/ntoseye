use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::WinObject,
    host::KvmHandle,
    memory,
    types::{Dtb, PhysAddr, VirtAddr},
};
use dashmap::DashMap;
use fst::{Automaton, IntoStreamer, Set, SetBuilder, Streamer, automaton::Str};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use pdb2::{FallibleIterator, PrimitiveKind, TypeData, TypeFinder, TypeIndex};
use pelite::{
    image::GUID,
    pe64::{Pe, debug::CodeView},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use spin::Mutex;
use std::{
    collections::HashMap,
    fs::File,
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use std::{fmt, io::Cursor};

// NOTE global is probably fine here?
pub static FORCE_DOWNLOADS: OnceLock<bool> = OnceLock::new();

#[derive(Default, Clone)]
pub struct SymbolIndex {
    set: Set<Vec<u8>>,
}

pub struct SymbolStore {
    pdbs: DashMap<u128, Mutex<pdb2::PDB<'static, Cursor<&'static [u8]>>>>,

    mmaps: DashMap<u128, Arc<Mmap>>,
    index: DashMap<u128, SymbolIndex>,
    index_types: DashMap<u128, SymbolIndex>,

    modules: DashMap<u64, LoadedModule>,
}

fn guid_to_u128(guid: GUID) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&guid.Data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&guid.Data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&guid.Data3.to_be_bytes());
    bytes[8..16].copy_from_slice(&guid.Data4);
    u128::from_be_bytes(bytes)
}

fn get_storage_directory() -> Option<PathBuf> {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("SUDO_USER")
                .ok()
                .map(|user| PathBuf::from(format!("/home/{}/.config", user)))
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| {
                        let mut path = PathBuf::from(home);
                        path.push(".config");
                        path
                    })
                })
        })?;

    let symbols_path = config_dir.join("ntoseye/symbols");
    std::fs::create_dir_all(&symbols_path).ok()?;

    Some(symbols_path)
}

/// Information needed to download a PDB file
#[derive(Clone)]
pub struct DownloadJob {
    pub url: String,
    pub path: PathBuf,
    pub filename: String,
}

impl DownloadJob {
    pub fn needs_download(&self) -> bool {
        !self.path.exists() || *FORCE_DOWNLOADS.get_or_init(|| false)
    }
}

fn download_pdb_with_progress(job: &DownloadJob, mp: &MultiProgress) -> Result<()> {
    if !job.needs_download() {
        return Ok(());
    }

    let response = reqwest::blocking::get(&job.url)?;
    let total_size = response.content_length().unwrap_or(0);

    let pb = mp.add(ProgressBar::new(total_size));
    pb.set_style(
        ProgressStyle::with_template("{msg} [{bar:40}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#-"),
    );

    pb.set_message(job.filename.clone());

    let mut file = File::create(&job.path)?;
    let mut downloaded = pb.wrap_read(response);

    std::io::copy(&mut downloaded, &mut file)?;
    pb.finish_and_clear();

    Ok(())
}

pub fn download_pdbs_parallel(jobs: Vec<DownloadJob>) -> Vec<Result<PathBuf>> {
    let mp = Arc::new(MultiProgress::new());

    jobs.into_par_iter()
        .map(|job| {
            if !job.needs_download() {
                return Ok(job.path);
            }

            let mp = Arc::clone(&mp);
            download_pdb_with_progress(&job, &mp).map(|_| job.path)
        })
        .collect::<Vec<_>>()
}

fn download_pdb_single(job: &DownloadJob) -> Result<()> {
    if !job.needs_download() {
        return Ok(());
    }

    let response = reqwest::blocking::get(&job.url)?;
    let total_size = response.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::with_template("{msg} [{bar:40}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#-"),
    );

    pb.set_message(job.filename.clone());

    let mut file = File::create(&job.path)?;
    let mut downloaded = pb.wrap_read(response);

    std::io::copy(&mut downloaded, &mut file)?;
    pb.finish_and_clear();

    Ok(())
}

#[derive(Debug, Clone)]
pub enum ParsedType {
    Primitive(String),
    Struct(String),
    Union(String),
    Enum(String),
    Pointer(Box<ParsedType>),
    Array(Box<ParsedType>, u32),
    Bitfield {
        underlying: Box<ParsedType>,
        pos: u8,
        len: u8,
    },
    Function(Box<ParsedType>, Vec<ParsedType>),
    Unknown,
}

impl fmt::Display for ParsedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedType::Primitive(s)
            | ParsedType::Struct(s)
            | ParsedType::Union(s)
            | ParsedType::Enum(s) => write!(f, "{}", s),
            // ParsedType::Pointer(inner) => write!(f, "{}*", inner),
            ParsedType::Pointer(inner) => {
                if let ParsedType::Function(ret_type, args) = &**inner {
                    write!(f, "{} (*)(", ret_type)?;
                    for (i, arg) in args.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", arg)?;
                    }
                    write!(f, ")")
                } else {
                    write!(f, "{}*", inner)
                }
            }
            ParsedType::Array(inner, count) => write!(f, "{}[{}]", inner, count),
            ParsedType::Bitfield {
                underlying,
                pos,
                len,
            } => write!(f, "{} : {} @ bit {}", underlying, len, pos),
            ParsedType::Function(ret_type, args) => {
                write!(f, "{} (", ret_type)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ")")
            }
            ParsedType::Unknown => write!(f, "<?>"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub offset: u32,
    #[allow(dead_code)]
    pub size: u64,
    pub type_data: ParsedType,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: usize,
    pub fields: HashMap<String, FieldInfo>,
}

impl TypeInfo {
    pub fn try_get_field_offset<S>(&self, field_name: S) -> Result<u64>
    where
        S: Into<String> + AsRef<str>,
    {
        self.fields
            .get(field_name.as_ref())
            .ok_or(Error::FieldNotFound(field_name.into()))
            .map(|f| f.offset as u64)
    }
}

/// A loaded module with its symbols and address range.
/// Used to track modules across both kernel and user address spaces.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub guid: u128,
    pub base_address: VirtAddr,
    pub size: u32,
    pub dtb: Dtb,
}

impl SymbolStore {
    pub fn new() -> Self {
        Self {
            pdbs: DashMap::new(),
            mmaps: DashMap::new(),
            index: DashMap::new(),
            index_types: DashMap::new(),
            modules: DashMap::new(),
        }
    }

    // TODO (everywhere) use MemoryOps, not KvmHandle...
    // TODO (everywhere) propagate errors with format!
    // NOTE dont check for more than 1 CV entry, there shouldn't be more than 1
    pub fn load_from_binary(
        &self,
        kvm: &KvmHandle,
        object: &mut WinObject,
    ) -> Result<Option<u128>> {
        let view = object.view(kvm).ok_or(Error::ViewFailed)?;
        let debug = view.debug()?;

        for entry in debug.iter().filter_map(|e| e.entry().ok()) {
            if let Some(CodeView::Cv70 {
                image,
                pdb_file_name,
            }) = entry.as_code_view()
            {
                let guid_str = format!(
                    "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    image.Signature.Data1,
                    image.Signature.Data2,
                    image.Signature.Data3,
                    image.Signature.Data4[0],
                    image.Signature.Data4[1],
                    image.Signature.Data4[2],
                    image.Signature.Data4[3],
                    image.Signature.Data4[4],
                    image.Signature.Data4[5],
                    image.Signature.Data4[6],
                    image.Signature.Data4[7],
                );

                let url = format!(
                    "https://msdl.microsoft.com/download/symbols/{}/{}{:X}/{}",
                    pdb_file_name, guid_str, image.Age, pdb_file_name
                );

                let stem = pdb_file_name
                    .to_str()
                    .ok()
                    .and_then(|s| s.split('.').next())
                    .unwrap_or("");

                let filename = format!("{}.{}{:X}.pdb", stem, guid_str, image.Age);
                let storage_dir = get_storage_directory().ok_or(Error::StorageNotFound)?;
                let path = storage_dir.join(&filename);

                let job = DownloadJob {
                    url,
                    path: path.clone(),
                    filename: format!("{}.pdb", stem),
                };
                download_pdb_single(&job)?;

                let guid = guid_to_u128(image.Signature);
                let file = File::open(&path)?;

                let mmap = unsafe { Mmap::map(&file)? };
                let mmap = Arc::new(mmap);
                let mmap_slice: &[u8] = &mmap;

                // we know `mmap` will live in `self.mmaps` as long as `self.pdbs` exists
                let static_slice: &'static [u8] = unsafe { std::mem::transmute(mmap_slice) };
                let cursor = Cursor::new(static_slice);

                let pdb = pdb2::PDB::open(cursor)?;

                self.mmaps.insert(guid, mmap);
                self.pdbs.insert(guid, pdb.into());

                self.build_index(guid);

                return Ok(Some(guid_to_u128(image.Signature)));
            }
        }

        Ok(None)
    }

    pub fn has_guid(&self, guid: u128) -> bool {
        self.pdbs.contains_key(&guid)
    }

    pub fn extract_download_job<B: MemoryOps<PhysAddr>>(
        backend: &B,
        dtb: Dtb,
        base_address: VirtAddr,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let addr_space = memory::AddressSpace::new(backend, dtb);
        let pe_image = crate::guest::read_pe_image(base_address, &addr_space)?;

        let view = pelite::pe64::PeView::from_bytes(&pe_image)?;

        let debug = view.debug()?;

        for entry in debug.iter().filter_map(|e| e.entry().ok()) {
            if let Some(CodeView::Cv70 {
                image,
                pdb_file_name,
            }) = entry.as_code_view()
            {
                let guid_str = format!(
                    "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    image.Signature.Data1,
                    image.Signature.Data2,
                    image.Signature.Data3,
                    image.Signature.Data4[0],
                    image.Signature.Data4[1],
                    image.Signature.Data4[2],
                    image.Signature.Data4[3],
                    image.Signature.Data4[4],
                    image.Signature.Data4[5],
                    image.Signature.Data4[6],
                    image.Signature.Data4[7],
                );

                let url = format!(
                    "https://msdl.microsoft.com/download/symbols/{}/{}{:X}/{}",
                    pdb_file_name, guid_str, image.Age, pdb_file_name
                );

                let stem = pdb_file_name
                    .to_str()
                    .ok()
                    .and_then(|s| s.split('.').next())
                    .unwrap_or("");

                let filename = format!("{}.{}{:X}.pdb", stem, guid_str, image.Age);
                let storage_dir = get_storage_directory().ok_or(Error::StorageNotFound)?;
                let path = storage_dir.join(&filename);

                let guid = guid_to_u128(image.Signature);
                let job = DownloadJob {
                    url,
                    path,
                    filename: format!("{}.pdb", stem),
                };

                return Ok(Some((job, guid)));
            }
        }

        Ok(None)
    }

    pub fn load_downloaded_pdb(
        &self,
        job: &DownloadJob,
        guid: u128,
        name: &str,
        base_address: VirtAddr,
        size: u32,
        dtb: Dtb,
    ) -> Result<u128> {
        if let Some(existing) = self.modules.get(&base_address.0) {
            return Ok(existing.guid);
        }

        if !self.pdbs.contains_key(&guid) {
            if !job.path.exists() {
                return Err(Error::PdbNotFound(job.path.clone()));
            }

            let file = File::open(&job.path)?;
            let mmap = unsafe { Mmap::map(&file)? };
            let mmap = Arc::new(mmap);
            let mmap_slice: &[u8] = &mmap;

            let static_slice: &'static [u8] = unsafe { std::mem::transmute(mmap_slice) };
            let cursor = Cursor::new(static_slice);

            let pdb = pdb2::PDB::open(cursor)?;

            self.mmaps.insert(guid, mmap);
            self.pdbs.insert(guid, pdb.into());

            self.build_index(guid);
        }

        let module = LoadedModule {
            name: name.to_string(),
            guid,
            base_address,
            size,
            dtb,
        };

        self.modules.insert(module.base_address.0, module);

        Ok(guid)
    }

    pub fn merged_symbol_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        let mut all_strings: Vec<String> = Vec::new();

        for module in self.modules.iter() {
            if let Some(filter_dtb) = dtb
                && module.dtb != filter_dtb
            {
                continue;
            }

            if let Some(index) = self.index.get(&module.guid) {
                let mut stream = index.set.stream();
                while let Some(key) = stream.next() {
                    if let Ok(s) = String::from_utf8(key.to_vec()) {
                        all_strings.push(s);
                    }
                }
            }
        }

        all_strings.sort();
        all_strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in all_strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap_or_default();
        let set = Set::new(bytes).unwrap_or_default();

        SymbolIndex { set }
    }

    pub fn merged_types_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        let mut all_strings: Vec<String> = Vec::new();

        for module in self.modules.iter() {
            if let Some(filter_dtb) = dtb
                && module.dtb != filter_dtb
            {
                continue;
            }

            if let Some(index) = self.index_types.get(&module.guid) {
                let mut stream = index.set.stream();
                while let Some(key) = stream.next() {
                    if let Ok(s) = String::from_utf8(key.to_vec()) {
                        all_strings.push(s);
                    }
                }
            }
        }

        all_strings.sort();
        all_strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in all_strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap_or_default();
        let set = Set::new(bytes).unwrap_or_default();

        SymbolIndex { set }
    }

    pub fn find_type_across_modules(&self, dtb: Dtb, type_name: &str) -> Option<TypeInfo> {
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }
            if let Some(type_info) = self.dump_struct_with_types(module.guid, type_name) {
                return Some(type_info);
            }
        }
        None
    }

    pub fn find_symbol_across_modules(&self, dtb: Dtb, symbol_name: &str) -> Option<VirtAddr> {
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }
            if let Some(rva) = self.get_rva_of_symbol(module.guid, symbol_name) {
                return Some(module.base_address + rva as u64);
            }
        }
        None
    }

    pub fn find_closest_symbol_for_address(
        &self,
        dtb: Dtb,
        address: VirtAddr,
    ) -> Option<(String, String, u32)> {
        use crate::guest::ModuleInfo;

        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }

            let module_end = module.base_address.0.saturating_add(module.size as u64);
            if address.0 >= module.base_address.0
                && address.0 < module_end
                && let Some((sym_name, offset)) =
                    self.get_address_of_closest_symbol(module.guid, module.base_address, address)
            {
                let short_name = ModuleInfo::derive_short_name(&module.name);
                return Some((short_name, sym_name, offset));
            }
        }
        None
    }

    fn build_index(&self, guid: u128) -> Option<()> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let mut symbols = symbol_table.iter();

        let mut strings: Vec<String> = Vec::new();

        while let Some(symbol) = symbols.next().ok()? {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse() {
                strings.push(data.name.to_string().into());
            }
        }

        strings.sort();
        strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap();
        let set = Set::new(bytes).unwrap();

        self.index.insert(guid, SymbolIndex { set });

        // NOW FOR TYPES!
        let mut strings: Vec<String> = Vec::new();

        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Class(class)) = typ.parse()
                && !class.properties.forward_reference()
                && class.name.to_string() != "<anonymous-tag>"
            {
                strings.push(class.name.to_string().into());
            }
        }

        strings.sort();
        strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap();
        let set = Set::new(bytes).unwrap();

        self.index_types.insert(guid, SymbolIndex { set });

        Some(())
    }

    // pub fn symbol_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
    //     self.index.get(&guid).map(|v| Arc::new(v.clone()))
    // }

    // pub fn types_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
    //     self.index_types.get(&guid).map(|v| Arc::new(v.clone()))
    // }

    pub fn get_rva_of_symbol<S>(&self, guid: u128, symbol_name: S) -> Option<u32>
    where
        S: AsRef<str>,
    {
        let symbol_name = symbol_name.as_ref();

        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let address_map = pdb_lock.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        while let Some(symbol) = symbols.next().ok()? {
            match symbol.parse() {
                Ok(pdb2::SymbolData::Public(data)) => {
                    if data.name.to_string() == symbol_name {
                        return Some(data.offset.to_rva(&address_map).unwrap_or_default().0);
                    }
                }
                Ok(pdb2::SymbolData::Data(_data)) => {
                    // TODO does this need to also be checked?
                }
                _ => {}
            }
        }

        None
    }

    pub fn get_address_of_closest_symbol(
        &self,
        guid: u128,
        base_address: VirtAddr,
        address: VirtAddr,
    ) -> Option<(String, u32)> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let address_map = pdb_lock.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        let mut closest: Option<(String, u32)> = None;
        let max_offset = 8192u32;

        while let Some(symbol) = symbols.next().ok()? {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse()
                && let Some(rva) = data.offset.to_rva(&address_map)
            {
                let symbol_address = base_address + rva.0 as u64;
                if address.0 >= symbol_address.0 {
                    let offset = (address.0 - symbol_address.0) as u32;
                    if offset <= max_offset {
                        if let Some((_, best_offset)) = closest {
                            if offset < best_offset {
                                closest = Some((data.name.to_string().into(), offset));
                            }
                        } else {
                            closest = Some((data.name.to_string().into(), offset));
                        }
                    }
                }
            }
        }

        closest
    }

    fn get_type_size<'p>(
        &self,
        finder: &pdb2::TypeFinder<'p>,
        index: pdb2::TypeIndex,
        ptr_size: u64,
    ) -> pdb2::Result<u64> {
        let item = finder.find(index)?;
        match item.parse()? {
            pdb2::TypeData::Primitive(data) => match data.kind {
                pdb2::PrimitiveKind::Void => Ok(0),

                pdb2::PrimitiveKind::Char
                | pdb2::PrimitiveKind::RChar
                | pdb2::PrimitiveKind::UChar
                | pdb2::PrimitiveKind::I8
                | pdb2::PrimitiveKind::U8
                | pdb2::PrimitiveKind::Bool8 => Ok(1),

                pdb2::PrimitiveKind::WChar
                | pdb2::PrimitiveKind::RChar16
                | pdb2::PrimitiveKind::Short
                | pdb2::PrimitiveKind::UShort
                | pdb2::PrimitiveKind::I16
                | pdb2::PrimitiveKind::U16 => Ok(2),

                pdb2::PrimitiveKind::Long
                | pdb2::PrimitiveKind::ULong
                | pdb2::PrimitiveKind::I32
                | pdb2::PrimitiveKind::U32
                | pdb2::PrimitiveKind::Bool32
                | pdb2::PrimitiveKind::F32
                | pdb2::PrimitiveKind::RChar32 => Ok(4),

                pdb2::PrimitiveKind::Quad
                | pdb2::PrimitiveKind::UQuad
                | pdb2::PrimitiveKind::I64
                | pdb2::PrimitiveKind::U64
                | pdb2::PrimitiveKind::F64 => Ok(8),

                pdb2::PrimitiveKind::Octa | pdb2::PrimitiveKind::UOcta => Ok(16),

                _ => Ok(0),
            },
            pdb2::TypeData::Class(data) => Ok(data.size), // NOTE this might (probably will) return 0
            pdb2::TypeData::Union(data) => Ok(data.size), // FIXME possibly? ^^
            pdb2::TypeData::Pointer(_) => Ok(ptr_size),
            pdb2::TypeData::Modifier(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Enumeration(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Array(data) => {
                Ok(data.dimensions.iter().fold(0, |acc, &x| acc + x as u64))
            }
            pdb2::TypeData::Bitfield(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Procedure(_) => Ok(ptr_size),
            _ => Ok(0),
        }
    }

    fn resolve_type<'p>(
        &self,
        finder: &TypeFinder<'p>,
        index: TypeIndex,
    ) -> pdb2::Result<ParsedType> {
        let item = finder.find(index)?;
        let parsed = item.parse()?;

        match parsed {
            pdb2::TypeData::Primitive(data) => {
                let name = match data.kind {
                    PrimitiveKind::Void => "void",
                    PrimitiveKind::Char | PrimitiveKind::I8 => "CHAR",
                    PrimitiveKind::UChar | PrimitiveKind::U8 => "UCHAR",
                    PrimitiveKind::RChar => "CHAR",
                    PrimitiveKind::WChar => "WCHAR",
                    PrimitiveKind::RChar16 => "char16_t",
                    PrimitiveKind::RChar32 => "char32_t",
                    PrimitiveKind::Short | PrimitiveKind::I16 => "SHORT",
                    PrimitiveKind::UShort | PrimitiveKind::U16 => "USHORT",
                    PrimitiveKind::Long | PrimitiveKind::I32 => "LONG",
                    PrimitiveKind::ULong | PrimitiveKind::U32 => "ULONG",
                    PrimitiveKind::Quad | PrimitiveKind::I64 => "LONGLONG",
                    PrimitiveKind::UQuad | PrimitiveKind::U64 => "ULONGLONG",
                    PrimitiveKind::Octa => "INT128",
                    PrimitiveKind::UOcta => "UINT128",
                    PrimitiveKind::F32 => "float",
                    PrimitiveKind::F64 => "double",
                    PrimitiveKind::Bool8 | PrimitiveKind::Bool32 => "bool",
                    _ => "__unknown_t",
                };
                Ok(ParsedType::Primitive(
                    name.to_string() + data.indirection.map_or("", |_| "*"),
                ))
            }

            TypeData::Class(data) => Ok(ParsedType::Struct(data.name.to_string().into_owned())),
            TypeData::Union(data) => Ok(ParsedType::Union(data.name.to_string().into_owned())),
            TypeData::Enumeration(data) => Ok(ParsedType::Enum(data.name.to_string().into_owned())),

            TypeData::Pointer(data) => {
                let inner = self.resolve_type(finder, data.underlying_type)?;
                Ok(ParsedType::Pointer(Box::new(inner)))
            }

            TypeData::Array(data) => {
                let inner = self.resolve_type(finder, data.element_type)?;
                let count = data.dimensions.first().unwrap_or(&0);
                let mut sizeof_type = self.get_type_size(finder, data.element_type, 8)? as u32;
                if sizeof_type == 0 {
                    sizeof_type = 1;
                }

                Ok(ParsedType::Array(Box::new(inner), count / sizeof_type))
            }

            TypeData::Modifier(data) => self.resolve_type(finder, data.underlying_type),
            TypeData::Bitfield(data) => {
                let inner = self.resolve_type(finder, data.underlying_type)?;

                Ok(ParsedType::Bitfield {
                    underlying: Box::new(inner),
                    pos: data.position,
                    len: data.length,
                })
            }

            pdb2::TypeData::Procedure(data) => {
                let return_type = if let Some(idx) = data.return_type {
                    self.resolve_type(finder, idx)?
                } else {
                    ParsedType::Primitive("void".to_string())
                };

                let mut args = Vec::new();
                if let Ok(arg_item) = finder.find(data.argument_list)
                    && let Ok(pdb2::TypeData::ArgumentList(list)) = arg_item.parse()
                {
                    for arg_idx in list.arguments {
                        let arg_type = self.resolve_type(finder, arg_idx)?;
                        args.push(arg_type);
                    }
                }

                Ok(ParsedType::Function(Box::new(return_type), args))
            }

            _ => Ok(ParsedType::Unknown),
        }
    }

    fn process_field_list<'p>(
        &self,
        type_finder: &pdb2::TypeFinder<'p>,
        field_index: pdb2::TypeIndex,
        fields_map: &mut HashMap<String, FieldInfo>,
    ) -> pdb2::Result<()> {
        let field_item = type_finder.find(field_index)?;

        if let Ok(TypeData::FieldList(list)) = field_item.parse() {
            for field in list.fields {
                if let TypeData::Member(member) = field {
                    let name = member.name.to_string().into_owned();
                    let offset = member.offset;

                    let type_info = self.resolve_type(type_finder, member.field_type)?;

                    fields_map.insert(
                        name,
                        FieldInfo {
                            offset: offset as u32,
                            size: self.get_type_size(type_finder, member.field_type, 8)?,
                            type_data: type_info,
                        },
                    );
                }
            }

            if let Some(more_fields) = list.continuation {
                self.process_field_list(type_finder, more_fields, fields_map)?;
            }
        }
        Ok(())
    }

    pub fn dump_struct_with_types<S>(&self, guid: u128, struct_name: S) -> Option<TypeInfo>
    where
        S: Into<String> + AsRef<str>,
    {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Class(class)) = typ.parse()
                && class.name.to_string() == struct_name.as_ref()
                && !class.properties.forward_reference()
            {
                let mut fields_map: HashMap<String, FieldInfo> = HashMap::new();
                if let Some(field_index) = class.fields {
                    self.process_field_list(&type_finder, field_index, &mut fields_map)
                        .ok()?;
                }

                return Some(TypeInfo {
                    name: struct_name.into(),
                    size: class.size as usize,
                    fields: fields_map,
                });
            }
        }

        None
    }
}

impl SymbolIndex {
    pub fn search(&self, prefix: &str, limit: usize) -> Vec<String> {
        let matcher = Str::new(prefix).starts_with();
        let mut stream = self.set.search(matcher).into_stream();
        let mut results = Vec::new();

        while let Some(key) = stream.next() {
            if let Ok(s) = String::from_utf8(key.to_vec()) {
                results.push(s);
            }

            if results.len() >= limit {
                break;
            }
        }

        results
    }
}
