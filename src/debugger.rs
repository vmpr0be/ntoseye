use std::{
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    backend::MemoryOps,
    guest::{Guest, WinObject},
    host::KvmHandle,
    symbols::SymbolStore,
    types::{PageTableEntry, Value, VirtAddr},
};

pub struct DebuggerContext {
    pub kvm: KvmHandle,
    pub symbols: SymbolStore,
    pub guest: Guest,
    pub current_process: Option<WinObject>,
}

pub struct DebuggerStartupMessage {
    pub build_number: Value<u16>,
    pub base_address: VirtAddr,
    pub loaded_module_list: VirtAddr,
}

pub struct DebuggerPte {
    name: String, // TODO maybe enum instead?
    address: VirtAddr,
    value: PageTableEntry,
}

pub struct DebuggerPteTraversal {
    pub address: VirtAddr,
    pub pxe: DebuggerPte,
    pub ppe: DebuggerPte,
    pub pde: Option<DebuggerPte>,
    pub pte: Option<DebuggerPte>,
}

pub struct DebuggerArgument {
    value: DebuggerArgumentValue,
    deref: bool,
}

pub enum DebuggerArgumentValue {
    Address(u64),
    Symbol(String),
}

impl DebuggerArgument {
    pub fn new(input: &str) -> Self {
        let (deref, input) = match input.strip_prefix('*') {
            Some(rest) => (true, rest),
            None => (false, input),
        };

        let value = if Self::is_decimal(input) {
            match input.parse::<u64>() {
                Ok(addr) => DebuggerArgumentValue::Address(addr),
                Err(_) => DebuggerArgumentValue::Symbol(input.to_string()),
            }
        } else if Self::is_hex(input) {
            let hex_str = input
                .strip_prefix("0x")
                .or_else(|| input.strip_prefix("0X"))
                .unwrap_or(input);

            match u64::from_str_radix(hex_str, 16) {
                Ok(addr) => DebuggerArgumentValue::Address(addr),
                Err(_) => DebuggerArgumentValue::Symbol(input.to_string()),
            }
        } else {
            DebuggerArgumentValue::Symbol(input.to_string())
        };

        Self { value, deref }
    }

    fn is_hex(s: &str) -> bool {
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);

        !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn is_decimal(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
    }

    pub fn resolve(&self, context: &DebuggerContext) -> Result<VirtAddr, String> {
        match &self.value {
            DebuggerArgumentValue::Address(addr) => {
                if !self.deref {
                    Ok(VirtAddr(*addr))
                } else {
                    let mem = context.get_current_process().memory(&context.kvm);
                    let val: VirtAddr = mem.read(VirtAddr(*addr))?;
                    Ok(val)
                }
            }
            DebuggerArgumentValue::Symbol(sym) => {
                if !self.deref {
                    Ok(context
                        .get_current_process()
                        .symbol(&context.symbols, sym)?
                        .address())
                } else {
                    let addr = context
                        .get_current_process()
                        .symbol(&context.symbols, sym)?
                        .address();
                    let mem = context.get_current_process().memory(&context.kvm);
                    let val: VirtAddr = mem.read(addr)?;
                    Ok(val)
                }
            }
        }
    }
}

impl DebuggerContext {
    pub fn new() -> Result<Self, String> {
        let kvm = KvmHandle::new()?;
        let mut symbols = SymbolStore::new();
        let guest = Guest::new(&kvm, &mut symbols)?;

        Ok(Self {
            kvm,
            symbols,
            guest,
            current_process: None,
        })
    }

    pub fn get_current_process(&self) -> &WinObject {
        match &self.current_process {
            Some(p) => p,
            None => &self.guest.ntoskrnl,
        }
    }

    pub fn get_startup_message_data(&mut self) -> Result<DebuggerStartupMessage, String> {
        let build_number = self
            .guest
            .ntoskrnl
            .symbol(&self.symbols, "NtBuildNumber")?
            .read(&self.kvm)?;
        let base_address = self.guest.ntoskrnl.base_address;
        let loaded_module_list = self
            .guest
            .ntoskrnl
            .symbol(&self.symbols, "PsLoadedModuleList")?
            .read(&self.kvm)?;

        Ok(DebuggerStartupMessage {
            build_number: Value(build_number),
            base_address,
            loaded_module_list,
        })
    }

    pub fn pte_traverse(&self, address: DebuggerArgument) -> Result<DebuggerPteTraversal, String> {
        let address = address.resolve(self)?;
        let process = &self.guest.ntoskrnl;
        let memory = process.memory(&self.kvm);

        let pte_base: VirtAddr = process
            .symbol(&self.symbols, "MmPteBase")?
            .read(&self.kvm)?;
        let pde_base = pte_base + (pte_base.0 >> 9 & 0x7FFFFFFFFF);
        let ppe_base = pde_base + (pde_base.0 >> 9 & 0x3FFFFFFF);
        let pxe_base = ppe_base + (ppe_base.0 >> 9 & 0x1FFFFF);

        let pxe_address = VirtAddr(pxe_base.0 + (((address.0 >> 39) & 0x1FF) << 3));
        let ppe_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 30) << 3) + ppe_base.0);

        let pxe_value: PageTableEntry = memory
            .read(pxe_address)
            .map_err(|e| format!("bad virtual address ({})", e))?;
        let ppe_value: PageTableEntry = memory
            .read(ppe_address)
            .map_err(|e| format!("bad pxe? ({})", e))?;

        let pxe = DebuggerPte {
            name: "PXE".into(),
            address: pxe_address,
            value: pxe_value,
        };
        let ppe = DebuggerPte {
            name: "PPE".into(),
            address: ppe_address,
            value: ppe_value,
        };

        if ppe_value.is_large_page() {
            return Ok(DebuggerPteTraversal {
                address,
                pxe,
                ppe,
                pde: None,
                pte: None,
            });
        }

        let pde_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 21) << 3) + pde_base.0);
        let pde_value: PageTableEntry = memory.read(pde_address)?;
        let pde = DebuggerPte {
            name: "PDE".into(),
            address: pde_address,
            value: pde_value,
        };

        if pde_value.is_large_page() {
            return Ok(DebuggerPteTraversal {
                address,
                pxe,
                ppe,
                pde: Some(pde),
                pte: None,
            });
        }

        let pte_address = VirtAddr(((address.0 & 0xFFFFFFFFFFFF) >> 12) << 3) + pte_base.0;
        let pte_value: PageTableEntry = memory.read(pte_address)?;
        let pte = DebuggerPte {
            name: "PTE".into(),
            address: pte_address,
            value: pte_value,
        };

        return Ok(DebuggerPteTraversal {
            address,
            pxe,
            ppe,
            pde: Some(pde),
            pte: Some(pte),
        });
    }
}

impl fmt::Display for DebuggerPte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = format!("pfn {:<5x} {:>11}", self.value.pfn(), self.value.flags());
        write!(
            f,
            "{}\n{}\n{}",
            format!("{} at {:X}", self.name, self.address),
            format!("contains {:016X}", Value(self.value.0)),
            flags
        )
    }
}
