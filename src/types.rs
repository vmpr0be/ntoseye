use owo_colors::OwoColorize;
use std::{
    fmt,
    ops::{Add, BitAnd, BitOr, Shr, Sub},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Clone, Copy, Debug, PartialEq, FromBytes, IntoBytes, Immutable)]
pub struct VirtAddr(pub u64);

pub type PhysAddr = u64;

pub type Dtb = PhysAddr;

#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct PageTableEntry(pub u64);

impl VirtAddr {
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl Add<u64> for VirtAddr {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        VirtAddr(self.0 + rhs)
    }
}

impl Sub<u64> for VirtAddr {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self {
        VirtAddr(self.0 - rhs)
    }
}

impl BitAnd<u64> for VirtAddr {
    type Output = Self;
    fn bitand(self, rhs: u64) -> Self {
        VirtAddr(self.0 & rhs)
    }
}

impl BitOr<u64> for VirtAddr {
    type Output = Self;
    fn bitor(self, rhs: u64) -> Self {
        VirtAddr(self.0 | rhs)
    }
}

impl Shr<u64> for VirtAddr {
    type Output = Self;
    fn shr(self, rhs: u64) -> Self {
        VirtAddr(self.0 >> rhs)
    }
}

impl VirtAddr {
    pub fn pml4e_index(self) -> u64 {
        (self.0 >> 39) & 0x1ff
    }

    pub fn pdpte_index(self) -> u64 {
        (self.0 >> 30) & 0x1ff
    }

    pub fn pde_index(self) -> u64 {
        (self.0 >> 21) & 0x1ff
    }

    pub fn pte_index(self) -> u64 {
        (self.0 >> 12) & 0x1ff
    }

    pub fn page_offset(self) -> u64 {
        const PAGE_OFFSET_SIZE: u32 = 12;
        self.0 & !(!0 << PAGE_OFFSET_SIZE)
    }
}

impl PageTableEntry {
    pub fn is_present(self) -> bool {
        self.0 & 1 != 0
    }

    pub fn is_large_page(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub fn pte_frame_addr(self) -> u64 {
        self.0 & 0x0000_ffff_ffff_f000u64
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn is_kernel_table(self) -> bool {
        // TODO split up into:
        // is_present, is_writable, is_user, is_large_page, nx
        (self.0 & 0x8000000000000087) == 0x03
    }

    pub fn is_self_ref(self, pa: u64) -> bool {
        (self.0 & 0x0000fffffffff083) == (pa | 0x03)
    }

    pub fn pfn(self) -> u64 {
        // Page Frame Number is the physical address shifted right by 12 bits (4KB page size)
        self.pte_frame_addr() >> 12
        // (self.0 >> 12) & 0x0000_000f_ffff_ffff
    }

    pub fn flags(self) -> String {
        format!(
            "{}{}{}{}{}{}{}{}{}{}{}",
            if self.0 & (1 << 9) != 0 { 'C' } else { '-' }, // CopyOnWrite
            if self.0 & (1 << 8) != 0 { 'G' } else { '-' }, // Global
            if self.0 & (1 << 7) != 0 { 'L' } else { '-' }, // LargePage
            if self.0 & (1 << 6) != 0 { 'D' } else { '-' }, // Dirty
            if self.0 & (1 << 5) != 0 { 'A' } else { '-' }, // Accessed
            if self.0 & (1 << 4) != 0 { 'N' } else { '-' }, // CacheDisable
            '-', // WriteThrough (always '-' in reference)
            if self.0 & (1 << 2) != 0 { 'U' } else { 'K' }, // Owner (User/Kernel)
            if self.0 & (1 << 11) != 0 { 'W' } else { 'R' }, // Write
            if self.0 & (1 << 63) != 0 { '-' } else { 'E' }, // NoExecute (inverted)
            if self.0 & 1 != 0 { 'V' } else { '-' }, // Valid
        )
    }
}

pub struct Value<T>(pub T);

/// Macro to implement formatting traits with a specific color
macro_rules! impl_colored_fmt {
    (impl<$g:ident> $t:ty, $color:ident, $($trait:path),+) => {
        $(
            impl<$g> $trait for $t
            where $g: $trait
            {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    <_ as $trait>::fmt(&self.0.$color(), f)
                }
            }
        )*
    };

    ($t:ty, $color:ident, $($trait:path),+) => {
        $(
            impl $trait for $t {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    <_ as $trait>::fmt(&self.0.$color(), f)
                }
            }
        )*
    };
}

impl_colored_fmt!(
    VirtAddr,
    yellow,
    fmt::Display,
    fmt::LowerHex,
    fmt::UpperHex,
    fmt::Binary
);

impl_colored_fmt!(
    impl<T> Value<T>,
    cyan,
    fmt::Display, fmt::LowerHex, fmt::UpperHex, fmt::Binary
);
