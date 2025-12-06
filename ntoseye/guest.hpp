#pragma once

#include "mem.hpp"
#include "util.hpp"

#include <cstdint>
#include <string>

namespace guest {
    bool initialize();

    mem::process get_ntoskrnl_process();

    std::vector<util::module> get_kernel_modules();

    bool query_process_basic_info(uint64_t &physical_process, uint64_t &virtual_process, mem::process &current_process);
    mem::process find_process(const std::string &name);

    uint64_t get_pxe_address(uint64_t va);
    uint64_t get_ppe_address(uint64_t va);
    uint64_t get_pde_address(uint64_t va);
    uint64_t get_pte_address(uint64_t va);
}