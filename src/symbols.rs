use crate::{guest::WinObject, host::KvmHandle, types::VirtAddr};
use fst::{Automaton, IntoStreamer, Set, SetBuilder, Streamer, automaton::Str};
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use pdb::{ClassType, FallibleIterator, PrimitiveKind, TypeData, TypeFinder, TypeIndex};
use pelite::{
    image::GUID,
    pe64::{Pe, debug::CodeView},
};
use reqwest;
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{File, copy},
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};
use std::{fmt, io::Cursor};

// NOTE global is probably fine here?
pub static FORCE_DOWNLOADS: OnceLock<bool> = OnceLock::new();

#[derive(Default, Clone)]
pub struct SymbolIndex {
    set: Set<Vec<u8>>,
}

pub struct SymbolStore {
    // NOTE im not sure RefCell was the best solution here; however,
    // the PDB type contains many functions which require &mut self,
    // and that was littering code in other places with mut where there
    // shouldn't be anything mutated.
    pdbs: HashMap<u128, RefCell<pdb::PDB<'static, Cursor<&'static [u8]>>>>,

    mmaps: HashMap<u128, Arc<Mmap>>,
    index: HashMap<u128, SymbolIndex>,
    index_types: HashMap<u128, SymbolIndex>,
    // index_processes: SymbolIndex
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

// TODO async?
fn download_pdb(
    url: &str,
    path: &PathBuf,
    filename: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() && !*FORCE_DOWNLOADS.get_or_init(|| false) {
        return Ok(());
    }

    let response = reqwest::blocking::get(url)?;
    let total_size = response.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::with_template("{msg} [{bar:40}] {bytes}/{total_bytes} ({eta})")?
            .progress_chars("#-"),
    );

    pb.set_message(filename.to_string());

    let mut file = File::create(path)?;
    let mut downloaded = pb.wrap_read(response);

    std::io::copy(&mut downloaded, &mut file)?;

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
    pub size: u64,
    pub type_data: ParsedType,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: usize,
    pub fields: HashMap<String, FieldInfo>,
}

impl SymbolStore {
    pub fn new() -> Self {
        Self {
            pdbs: HashMap::new(),
            mmaps: HashMap::new(),
            index: HashMap::new(),
            index_types: HashMap::new(),
        }
    }

    // TODO (everywhere) use MemoryOps, not KvmHandle...
    // TODO (everywhere) propagate errors with format!
    // NOTE dont check for more than 1 CV entry, there shouldn't be more than 1
    pub fn load_from_binary(
        &mut self,
        kvm: &KvmHandle,
        object: &mut WinObject,
    ) -> Result<u128, String> {
        let view = object
            .view(kvm)
            .ok_or("failed to view object".to_string())?;
        let debug = view
            .debug()
            .ok()
            .ok_or("failed to get object debug section".to_string())?;

        for entry in debug.iter().filter_map(|e| e.entry().ok()) {
            if let Some(cv) = entry.as_code_view() {
                match cv {
                    CodeView::Cv70 {
                        image,
                        pdb_file_name,
                    } => {
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
                        let storage_dir =
                            get_storage_directory().ok_or("failed to get storage directory")?;
                        let path = storage_dir.join(filename);

                        download_pdb(&url, &path, format!("{}.pdb", stem))
                            .map_err(|e| e.to_string())?;

                        let guid = guid_to_u128(image.Signature);
                        let file = File::open(path).map_err(|e| e.to_string())?;

                        let mmap = unsafe { Mmap::map(&file).map_err(|e| e.to_string())? };
                        let mmap = Arc::new(mmap);
                        let mmap_slice: &[u8] = &mmap;

                        // we know `mmap` will live in `self.mmaps` as long as `self.pdbs` exists
                        let static_slice: &'static [u8] =
                            unsafe { std::mem::transmute(mmap_slice) };
                        let cursor = Cursor::new(static_slice);

                        let pdb = pdb::PDB::open(cursor).map_err(|e| e.to_string())?;

                        self.mmaps.insert(guid, mmap);
                        self.pdbs.insert(guid, pdb.into());

                        self.build_index(guid);

                        return Ok(guid_to_u128(image.Signature));
                    }
                    _ => (),
                }
            }
        }

        Err("no debug symbols found in binary".into())
    }

    fn build_index(&mut self, guid: u128) -> Option<()> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb = pdb.borrow_mut();
        let symbol_table = pdb.global_symbols().ok()?;
        let mut symbols = symbol_table.iter();

        let mut strings: Vec<String> = Vec::new();

        let pb = ProgressBar::new_spinner();

        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.black.bright} {msg}")
                .unwrap(),
        );

        pb.set_message(format!(
            "{}",
            owo_colors::OwoColorize::bright_black(&"Building index...")
        ));
        pb.enable_steady_tick(Duration::from_millis(100));

        while let Some(symbol) = symbols.next().ok()? {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    strings.push(data.name.to_string().into());
                }
                _ => {}
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

        let type_information = pdb.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Class(class)) = typ.parse() {
                if !class.properties.forward_reference()
                    && class.name.to_string() != "<anonymous-tag>"
                {
                    strings.push(class.name.to_string().into());
                }
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

        pb.finish_and_clear();

        Some(())
    }

    pub fn symbol_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
        self.index.get(&guid).map(|v| Arc::new(v.clone()))
    }

    pub fn types_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
        self.index_types.get(&guid).map(|v| Arc::new(v.clone()))
    }

    pub fn get_rva_of_symbol(&self, guid: u128, symbol_name: &str) -> Option<u32> {
        let pdb = self.pdbs.get(&guid)?;
        let mut pdb = pdb.borrow_mut();
        let symbol_table = pdb.global_symbols().ok()?;
        let address_map = pdb.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        while let Some(symbol) = symbols.next().ok()? {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    if data.name.to_string() == symbol_name {
                        return Some(data.offset.to_rva(&address_map).unwrap_or_default().0);
                    }
                }
                Ok(pdb::SymbolData::Data(data)) => {
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
        let pdb = self.pdbs.get(&guid)?;
        let mut pdb = pdb.borrow_mut();
        let symbol_table = pdb.global_symbols().ok()?;
        let address_map = pdb.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        let mut closest: Option<(String, u32)> = None;
        let max_offset = 8192u32;

        while let Some(symbol) = symbols.next().ok()? {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    if let Some(rva) = data.offset.to_rva(&address_map) {
                        let symbol_address = base_address + rva.0.into();
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
                _ => {}
            }
        }

        closest
    }

    fn get_type_size<'p>(
        &self,
        finder: &pdb::TypeFinder<'p>,
        index: pdb::TypeIndex,
        ptr_size: u64,
    ) -> pdb::Result<u64> {
        let item = finder.find(index)?;
        match item.parse()? {
            pdb::TypeData::Primitive(data) => match data.kind {
                pdb::PrimitiveKind::Void => Ok(0),

                pdb::PrimitiveKind::Char
                | pdb::PrimitiveKind::RChar
                | pdb::PrimitiveKind::UChar
                | pdb::PrimitiveKind::I8
                | pdb::PrimitiveKind::U8
                | pdb::PrimitiveKind::Bool8 => Ok(1),

                pdb::PrimitiveKind::WChar
                | pdb::PrimitiveKind::RChar16
                | pdb::PrimitiveKind::Short
                | pdb::PrimitiveKind::UShort
                | pdb::PrimitiveKind::I16
                | pdb::PrimitiveKind::U16 => Ok(2),

                pdb::PrimitiveKind::Long
                | pdb::PrimitiveKind::ULong
                | pdb::PrimitiveKind::I32
                | pdb::PrimitiveKind::U32
                | pdb::PrimitiveKind::Bool32
                | pdb::PrimitiveKind::F32
                | pdb::PrimitiveKind::RChar32 => Ok(4),

                pdb::PrimitiveKind::Quad
                | pdb::PrimitiveKind::UQuad
                | pdb::PrimitiveKind::I64
                | pdb::PrimitiveKind::U64
                | pdb::PrimitiveKind::F64 => Ok(8),

                pdb::PrimitiveKind::Octa | pdb::PrimitiveKind::UOcta => Ok(16),

                _ => Ok(0),
            },
            pdb::TypeData::Class(data) => Ok(data.size as u64), // NOTE this might (probably will) return 0
            pdb::TypeData::Union(data) => Ok(data.size as u64), // FIXME possibly? ^^
            pdb::TypeData::Pointer(_) => Ok(ptr_size),
            pdb::TypeData::Modifier(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb::TypeData::Enumeration(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb::TypeData::Array(data) => {
                Ok(data.dimensions.iter().fold(0, |acc, &x| acc + x as u64))
            }
            pdb::TypeData::Bitfield(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb::TypeData::Procedure(_) => Ok(ptr_size),
            _ => Ok(0),
        }
    }

    fn resolve_type<'p>(
        &self,
        finder: &TypeFinder<'p>,
        index: TypeIndex,
    ) -> pdb::Result<ParsedType> {
        let item = finder.find(index)?;
        let parsed = item.parse()?;

        match parsed {
            pdb::TypeData::Primitive(data) => {
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
                let count = data.dimensions.get(0).unwrap_or(&0).clone();
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

            pdb::TypeData::Procedure(data) => {
                let return_type = if let Some(idx) = data.return_type {
                    let t = self.resolve_type(finder, idx)?;
                    t
                } else {
                    ParsedType::Primitive("void".to_string())
                };

                let mut args = Vec::new();
                if let Ok(arg_item) = finder.find(data.argument_list) {
                    if let Ok(pdb::TypeData::ArgumentList(list)) = arg_item.parse() {
                        for arg_idx in list.arguments {
                            let arg_type = self.resolve_type(finder, arg_idx)?;
                            args.push(arg_type);
                        }
                    }
                }

                Ok(ParsedType::Function(Box::new(return_type), args))
            }

            _ => Ok(ParsedType::Unknown),
        }
    }

    fn process_field_list<'p>(
        &self,
        type_finder: &pdb::TypeFinder<'p>,
        field_index: pdb::TypeIndex,
        fields_map: &mut HashMap<String, FieldInfo>,
    ) -> pdb::Result<()> {
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

    pub fn dump_struct_with_types(&self, guid: u128, struct_name: &str) -> Option<TypeInfo> {
        let pdb = self.pdbs.get(&guid)?;
        let mut pdb = pdb.borrow_mut();

        let type_information = pdb.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Class(class)) = typ.parse() {
                if class.name.to_string() == struct_name && !class.properties.forward_reference() {
                    let mut fields_map = HashMap::new();
                    if let Some(field_index) = class.fields {
                        self.process_field_list(&type_finder, field_index, &mut fields_map)
                            .ok()?;
                    }

                    return Some(TypeInfo {
                        name: struct_name.to_string(),
                        size: class.size as usize,
                        fields: fields_map,
                    });
                }
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
