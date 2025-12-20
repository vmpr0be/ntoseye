#include "guest.hpp"
#include "pdb.hpp"
#include "util.hpp"
#include "host.hpp"
#include "mem.hpp"
#include "log.hpp"

#include "windefs.h"

#include <cassert>
#include <cstdint>
#include <limits>
#include <vector>
#include <set>

static uintptr_t mm_pte_base = 0;
static uintptr_t mm_pde_base = 0;
static uintptr_t mm_ppe_base = 0;
static uintptr_t mm_pxe_base = 0;
static uintptr_t mm_pxe_self = 0;

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((uintptr_t)1) << VIRTUAL_ADDRESS_BITS) - 1)
#define PTE_SHIFT 3
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PTI_MASK_AMD64 (PTE_PER_PAGE - 1)
#define PDI_MASK_AMD64 (PDE_PER_PAGE - 1)
#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define mi_get_pxe_offset(va) ((uint32_t)(((uintptr_t)(va) >> PXI_SHIFT) & PXI_MASK))

#define mi_get_pxe_address(va)   ((uint64_t)mm_pxe_base + mi_get_pxe_offset(va))

#define mi_get_ppe_address(va)   \
    ((uint64_t)(((((uintptr_t)(va) & VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + mm_ppe_base))

#define mi_get_pde_address(va)  \
    ((uint64_t)(((((uintptr_t)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + mm_pde_base))

#define mi_get_pte_address(va) \
    ((uint64_t)(((((uintptr_t)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + mm_pte_base))

static mem::process ntoskrnl_process;
static std::vector<util::symbol> ntoskrnl_symbols;

// TODO i dont like the magic numbers scattered about, should have intuitive names
// TODO function uses hardcoded 256 / 512, should use PTE_PER_PAGE?
static bool verify_pml4(const uint8_t *page, uint64_t pa)
{
    const uint64_t *ptes = reinterpret_cast<const uint64_t*>(page);
    int kernel_valid = 0;
    int user_zero = 0;
    int kernel_zero = 0;
    bool self_ref = false;

    // check user-mode PTEs (first 256 entries)
    for (int i = 0; i < 256; i++)
        if (ptes[i] == 0)
            user_zero++;

    // check kernel-mode PTEs (last 256 entries)
    for (int i = 256; i < 512; i++) {
        if (ptes[i] == 0) {
            kernel_zero++;
            continue;
        }

        // check for valid supervisor entry
        if ((ptes[i] & 0x8000000000000087ULL) == 0x03) {
            uint64_t pdpt_pa = mem::pte_to_pa(ptes[i]);

            if (pdpt_pa < 0x10000000000ULL)
                kernel_valid++;
        }

        // check for self-referential entry
        if ((ptes[i] & 0x0000fffffffff083ULL) == (pa | 0x03))
            self_ref = true;
    }

    return self_ref && (kernel_valid >= 6) && (user_zero > 0x40) && (kernel_zero > 0x40);
}

static bool scan_large_pages(
    uint64_t pa_table,
    uint64_t va_base,
    uint64_t va_min,
    uint64_t va_max,
    int level,
    uint64_t &out_va_base,
    uint64_t &out_size)
{
    static const uint64_t PML_REGION_SIZE[] = { 0, 12, 21, 30, 39 };

    if (level < 2)
        return false;

    std::vector<uint8_t> page(0x1000);
    if (!host::read_kvm_memory(page.data(), pa_table, 0x1000))
        return false;

    if (level == 4) {
        if (!verify_pml4(page.data(), pa_table))
            return false;

        va_base = 0;
        out_va_base = 0;
        out_size = 0;
    }

    const uint64_t *ptes = reinterpret_cast<const uint64_t*>(page.data());

    for (int i = 0; i < PTE_PER_PAGE; i++) {
        uint64_t va_current = mem::sign_extend_48bit(va_base + (static_cast<uint64_t>(i) << PML_REGION_SIZE[level]));

        if (out_va_base && (va_current > (out_va_base + out_size)))
            return out_size > 0;
        if (va_current < va_min)
            continue;
        if (va_current > va_max)
            return out_size > 0;

        uint64_t pte = ptes[i];

        if (!mem::is_pte_valid(pte))
            continue;

        if (level == 2) {
            if (!mem::is_large_page(pte))
                continue;

            if (out_va_base == 0)
                out_va_base = va_current;

            out_size += 0x200000; // 2 MiB
            continue;
        }

        if (mem::is_large_page(pte))
            continue;

        uint64_t next_table = mem::pte_to_pa(pte);
        if (scan_large_pages(next_table, va_current, va_min, va_max, level - 1, out_va_base, out_size))
            return true;
    }

    return out_size > 0;
}

static void scan_small_pages_worker(
    uint64_t pa_table,
    uint64_t va_base,
    uint64_t va_min,
    uint64_t va_max,
    int level,
    std::set<uint64_t> &candidates)
{
    static const uint64_t PML_REGION_SIZE[] = { 0, 12, 21, 30, 39 };

    if (level == 0)
        return;

    std::vector<uint8_t> page(0x1000);
    if (!host::read_kvm_memory(page.data(), pa_table, 0x1000))
        return;

    if (level == 4) {
        if (!verify_pml4(page.data(), pa_table))
            return;

        va_base = 0;
    }

    const uint64_t *ptes = reinterpret_cast<const uint64_t*>(page.data());

    for (int i = 0; i < PTE_PER_PAGE; i++) {
        uint64_t va_current = mem::sign_extend_48bit(va_base + (static_cast<uint64_t>(i) << PML_REGION_SIZE[level]));

        if (va_current < va_min)
            continue;
        if (va_current > va_max)
            return;

        uint64_t pte = ptes[i];
        if (!mem::is_pte_valid(pte))
            continue;

        if (level == 1) {
            // page i-1 is empty
            // page i is ACTIVE-WRITE-SUPERVISOR-NOEXECUTE 0x8000000000000003
            // pages i+1 to i+31 are ACTIVE-SUPERVISOR 0x01

            if (i == 0)
                continue;
            if (ptes[i - 1] != 0)
                continue;
            if ((pte & 0x800000000000000fULL) != 0x8000000000000003ULL)
                continue;

            bool valid = true;
            for (int j = i + 2; j < std::min(i + 32, 512); j++)
                if ((ptes[j] & 0x0f) != 0x01) {
                    valid = false;
                    break;
                }

            if (valid)
                candidates.insert(va_current);
            continue;
        }

        if (mem::is_large_page(pte))
            continue;

        uint64_t next_table = mem::pte_to_pa(pte);
        scan_small_pages_worker(next_table, va_current, va_min, va_max, level - 1, candidates);
    }
}

static auto get_ntoskrnl_base_address() -> uint64_t
{
    constexpr uint64_t KERNEL_VA_MIN = 0xfffff80000000000ULL;
    constexpr uint64_t KERNEL_VA_MAX = 0xfffff807ffffffffULL;

    for (uint64_t pa_dtb = 0x1000; pa_dtb < 0x1000000; pa_dtb += 0x1000) {
        std::vector<uint8_t> page(0x1000);
        if (!host::read_kvm_memory(page.data(), pa_dtb, 0x1000))
            continue;

        if (!verify_pml4(page.data(), pa_dtb))
            continue;

        ntoskrnl_process.set_dir_base(pa_dtb);

        uint64_t kernel_base = 0;
        uint64_t kernel_size = 0;

        if (scan_large_pages(pa_dtb, 0, KERNEL_VA_MIN, KERNEL_VA_MAX, 4, kernel_base, kernel_size)) {
            if (kernel_size >= 0x400000 && kernel_size < 0x1800000) {
                std::vector<uint8_t> kernel_buf(kernel_size);
                if (ntoskrnl_process.read_bytes(kernel_buf.data(), kernel_base, kernel_size)) {
                    for (size_t p = 0; p < kernel_size; p += 0x1000) {
                        // MZ
                        if (*(uint16_t*)(kernel_buf.data() + p) != 0x5a4d)
                            continue;

                        bool found_poolcode = false;
                        for (size_t o = 0; o < 0x1000; o += 8)
                            if (*(uint64_t*)(kernel_buf.data() + p + o) == 0x45444F434C4F4F50ULL) {
                                found_poolcode = true;
                                break;
                            }

                        if (found_poolcode)
                            return kernel_base + p;
                    }
                }
            }
        }

        out::warn("large page scan failed, trying small page scan\n");
        std::set<uint64_t> candidates;
        scan_small_pages_worker(pa_dtb, 0, KERNEL_VA_MIN, KERNEL_VA_MAX, 4, candidates);

        for (uint64_t va : candidates) {
            std::vector<uint8_t> page_buf(0x1000);
            if (!ntoskrnl_process.read_bytes(page_buf.data(), va, 0x1000))
                continue;

            // MZ
            if (*(uint16_t*)(page_buf.data()) != 0x5a4d)
                continue;

            // poolcode
            for (size_t o = 0; o < 0x1000; o += 8)
                if (*(uint64_t*)(page_buf.data() + o) == 0x45444F434C4F4F50ULL)
                    return va;
        }
    }

    return 0;
}

static uint16_t get_ntos_version()
{
    auto get_version = util::get_proc_address(ntoskrnl_symbols, "RtlGetVersion");

    std::vector<uint8_t> page(0x1000);
    if (!ntoskrnl_process.read_bytes(page.data(), get_version, 0x1000))
        return 0;

    auto buf = page.data();

    char major = 0, minor = 0;

    // rcx + 4, rcx + 8
    for (char* b = (char*)buf; b - (char*)buf < 0xf0; b++) {
        if (!major && !minor)
            if (*(uint32_t*)(void*)b == 0x441c748)
                return ((uint16_t)b[4]) * 100 + (b[5] & 0xf);
        if (!major && (*(uint32_t*)(void*)b & 0xfffff) == 0x441c7)
            major = b[3];
        if (!minor && (*(uint32_t*)(void*)b & 0xfffff) == 0x841c7)
            minor = b[3];
    }

    if (minor >= 100)
        minor = 0;

    return ((uint16_t)major) * 100 + minor;
}

static uint32_t get_ntos_build()
{
    uint64_t nt_build = util::get_proc_address(ntoskrnl_symbols, "NtBuildNumber");

    if (nt_build) {
        auto build = ntoskrnl_process.read<uint32_t>(nt_build);
        if (build)
            return build & 0xffffff;
    }

    uint64_t get_version = util::get_proc_address(ntoskrnl_symbols, "RtlGetVersion");

    std::vector<uint8_t> page(0x1000);
    if (!ntoskrnl_process.read_bytes(page.data(), get_version, 0x1000))
        return 0;

    auto buf = page.data();

    // rcx + 12
    for (char* b = (char*)buf; b - (char*)buf < 0xf0; b++) {
        uint32_t val = *(uint32_t*)(void*)b & 0xffffff;
        if (val == 0x0c41c7 || val == 0x05c01b)
            return *(uint32_t*)(void*)(b + 3);
    }

    return 0;
}

bool guest::initialize()
{
    // TODO make this a cleaner process, maybe dedicated ntoskrnl namespace
    ntoskrnl_process.base_address = get_ntoskrnl_base_address();
    if (!ntoskrnl_process.base_address) {
        out::error("failed to get ntoskrnl base address\n");
        return false;
    }

    ntoskrnl_symbols = util::get_process_exports(ntoskrnl_process);

    auto nt_version = get_ntos_version();
    auto nt_build = get_ntos_build();

    // REQUIRED, loads offsets
    pdb::load(ntoskrnl_process, pdb::process_priv::kernel);

    // TODO proper error handling for uninitialized offsets?
    assert(pdb::get_ntoskrnl_offsets().active_process_links != 0);
    assert(pdb::get_ntoskrnl_offsets().session != 0);
    assert(pdb::get_ntoskrnl_offsets().client_id != 0);
    assert(pdb::get_ntoskrnl_offsets().stack_count != 0);
    assert(pdb::get_ntoskrnl_offsets().image_filename != 0);
    assert(pdb::get_ntoskrnl_offsets().dir_base != 0);
    assert(pdb::get_ntoskrnl_offsets().peb != 0);
    assert(pdb::get_ntoskrnl_offsets().vad_root != 0);
    assert(pdb::get_ntoskrnl_offsets().parent_client_id != 0);
    assert(pdb::get_ntoskrnl_offsets().object_table != 0);

    auto initial_system_process = util::get_proc_address(ntoskrnl_symbols, "PsInitialSystemProcess");
    ntoskrnl_process.virtual_process = ntoskrnl_process.read<uint64_t>(initial_system_process);
    ntoskrnl_process.physical_process = ntoskrnl_process.virtual_to_physical(ntoskrnl_process.virtual_process);

    // set the basic process info of ntoskrnl, lil hack
    uint64_t a = 0, b = 0;
    query_process_basic_info(a, b, ntoskrnl_process);

    std::print("Windows Kernel Version {}\n", out::value(nt_build));
    std::print("Kernel base = {} PsLoadedModuleList = {}\n",
            out::address(ntoskrnl_process.base_address, out::fmt::x, out::prefix::with_prefix),
            out::address(util::get_proc_address(ntoskrnl_symbols, "PsLoadedModuleList"), out::fmt::x, out::prefix::with_prefix));

    uint8_t mi_get_pte_address_signature[] = "\x48\xc1\xe9\x09\x48\xb8\xf8\xff\xff\xff\x7f\x00\x00\x00\x48\x23\xc8\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xc1\xc3";
    char mi_get_pte_address_mask[] = "xxxxxxxxxxxxxxxxxxx????????xxxx";

    auto section = IMAGE_FIRST_SECTION(ntoskrnl_process.nt_headers);
    for (int i = 0; i < ntoskrnl_process.nt_headers->FileHeader.NumberOfSections; i++, section++) {
        section->Name[7] = 0;
        if (strcmp((char*)section->Name, ".text") == 0)
            break;
    }

    auto mi_get_pte_address = util::find_pattern(ntoskrnl_process, ntoskrnl_process.base_address + section->VirtualAddress, section->SizeOfRawData, mi_get_pte_address_signature, mi_get_pte_address_mask);

    mm_pte_base = ntoskrnl_process.read<uint64_t>(mi_get_pte_address + 0x13);
    mm_pde_base = mm_pte_base + (mm_pte_base >> 9 & 0x7FFFFFFFFF);
    mm_ppe_base = mm_pde_base + (mm_pde_base >> 9 & 0x3FFFFFFF);
    mm_pxe_base = mm_ppe_base + (mm_ppe_base >> 9 & 0x1FFFFF);
    mm_pxe_self = mm_pxe_base + (mm_pxe_base >> 9 & 0xFFF);

    return true;
}

mem::process guest::get_ntoskrnl_process()
{
    return ntoskrnl_process;
}

std::vector<util::module> guest::get_kernel_modules()
{
    PEB_LDR_DATA ldr = { 0 };
    ldr.InMemoryOrdermoduleList.Flink = util::get_proc_address(ntoskrnl_symbols, "PsLoadedModuleList");

    uint64_t head = 0;
    uint64_t end = 0;
    uint64_t prev = 0;

    LDR_MODULE ldr_module;

    std::vector<util::module> modules;

    while (util::query_module_basic_info(ntoskrnl_process, ldr, ldr_module, head, end, prev, false)) {
        auto module_wide_name = new short[ldr_module.BaseDllName.Length];
        ntoskrnl_process.read_bytes(module_wide_name, ldr_module.BaseDllName.Buffer, ldr_module.BaseDllName.Length * sizeof(short));

        std::string modulename;
        for (int i = 0; i < ldr_module.BaseDllName.Length; i++)
            modulename.push_back(((char*)module_wide_name)[i*2]);

        delete[] module_wide_name;

        modules.push_back({ ntoskrnl_process, modulename.c_str(), ldr_module.BaseAddress, ldr_module });
    }

    return modules;
}

bool guest::query_process_basic_info(uint64_t &physical_process, uint64_t &virtual_process, mem::process &current_process)
{
    if (physical_process == 0 && virtual_process == 0) {
        physical_process = ntoskrnl_process.physical_process;
        virtual_process = ntoskrnl_process.virtual_process;
    }
    else {
        virtual_process = host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().active_process_links) - pdb::get_ntoskrnl_offsets().active_process_links;
        if (!virtual_process)
            return false;

        physical_process = current_process.virtual_to_physical(virtual_process);
        if (!physical_process)
            return false;
    }

    current_process.process_id = host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().active_process_links - 8);
    current_process.physical_process = physical_process;
    current_process.virtual_process = virtual_process;

    current_process.set_dir_base(host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().dir_base));

    util::set_process_peb(current_process, pdb::get_ntoskrnl_offsets().peb);

    current_process.win_dbg_data.session_id = ntoskrnl_process.read<uint32_t>(
        host::read_kvm_memory<uint64_t>(
            physical_process + pdb::get_ntoskrnl_offsets().session
        ) + pdb::get_ntoskrnl_offsets().session_id
    );
    current_process.win_dbg_data.client_id = host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().client_id);
    current_process.win_dbg_data.peb_address = host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().peb);
    current_process.win_dbg_data.parent_client_id = host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().parent_client_id);
    current_process.win_dbg_data.object_table_address = host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().object_table);

    return true;
}

mem::process guest::find_process(const std::string &name)
{
    uint64_t physical_process = 0;
    uint64_t virtual_process = 0;
    mem::process current_process;

    while (query_process_basic_info(physical_process, virtual_process, current_process)) {
        auto stack_count = host::read_kvm_memory<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().stack_count);

        if (current_process.process_id < std::numeric_limits<int>::max() && stack_count) {
            auto base_module = util::get_module(current_process, {});

            if (name == base_module.name.c_str()) {

                auto physical_vad_root = physical_process + pdb::get_ntoskrnl_offsets().vad_root;
                auto vad_count = current_process.read<uint64_t>(physical_process + pdb::get_ntoskrnl_offsets().vad_root + 0x10);

                std::vector<uint64_t> visit;

                visit.push_back(physical_vad_root);

                while (visit.size() != 0) {
                    auto virtual_vad = host::read_kvm_memory<uintptr_t>(visit.back());
                    visit.pop_back();

                    if (!virtual_vad)
                        continue;

                    auto physical_vad = current_process.virtual_to_physical(virtual_vad);
                    visit.push_back(physical_vad + 0);
                    visit.push_back(physical_vad + 8);

                    auto short_vad = host::read_kvm_memory<MMVAD_SHORT>(physical_vad);

                    if (util::is_vad_short(short_vad)) {
                        MMVAD full_vad = { 0 };
                        full_vad.Core = short_vad;

                        current_process.vad_list.push_back(full_vad);
                    }
                    else {
                        current_process.vad_list.push_back(host::read_kvm_memory<MMVAD>(physical_vad));
                    }
                }

                current_process.base_address = base_module.base_address;

                return current_process;
            }
        }
    }

    return {};
}

uint64_t guest::get_pxe_address(uint64_t va)
{
    auto x = ((PMMPTE)mm_pxe_base + (((uint64_t)va >> 39) & 0x1FF));
    return *reinterpret_cast<uint64_t*>(&x);
}

uint64_t guest::get_ppe_address(uint64_t va)
{
    return mi_get_ppe_address(va);
}

uint64_t guest::get_pde_address(uint64_t va)
{
    return mi_get_pde_address(va);
}

uint64_t guest::get_pte_address(uint64_t va)
{
    return mi_get_pte_address(va);
}
