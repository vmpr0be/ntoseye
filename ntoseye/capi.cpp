#include "capi.hpp"
#include "cmd.hpp"
#include "config.hpp"
#include "mem.hpp"

#include <algorithm>
#include <print>
#include <filesystem>
#include <map>

#include <dlfcn.h>

#include <ntoseye/ntoseye.h>

#define EXPORT __attribute__((visibility("default")))

static NTProcess nt_process;
static std::map<std::string, NTCallbackProc> plugin_callbacks;

static cmd::status rerouter(const std::vector<std::string> &args, mem::process &proc)
{
    nt_process = &proc;
    if (plugin_callbacks.contains(cmd::get_current_command())) {
        int argc = args.size();
        char **argv = new char*[argc];

        for (int i = 0; i < argc; i++)
            argv[i] = (char*)args[i].c_str();

        auto res = cmd::status(cmd::status_code(plugin_callbacks[cmd::get_current_command()](argc, argv)));
        delete[] argv;
        return res;
    }

    return cmd::status::unknown_command(cmd::get_current_command());
}

extern "C" EXPORT NTProcess NT_GetCurrentProcess()
{
    return nt_process;
}

extern "C" EXPORT int NT_RegisterCallback(NTCallbackProc proc, char *name)
{
    auto cmd = std::format(":{}", name);
    
    if (plugin_callbacks.contains(cmd))
        return 0;
    
    plugin_callbacks[cmd] = proc;
    cmd::register_callback(cmd, rerouter);

    return 1;
}

extern "C" EXPORT uint64_t NT_ProcessGetBaseAddress(NTProcess process)
{
    mem::process *ntproc = reinterpret_cast<mem::process*>(process);
    return ntproc->base_address;
}

bool capi::initialize()
{
    auto plugins_directory = std::format("{}/plugins", config::get_storage_directory());
    std::filesystem::create_directories(plugins_directory);

    /*
     * to-do: ask user if they really wanna load the plugin?
     */
    std::ranges::all_of(std::filesystem::directory_iterator(plugins_directory),
                        [&](auto dir_entry) {
                            if (!dir_entry.is_regular_file())
                                return true;

                            dlopen(dir_entry.path().c_str(), RTLD_LAZY);
                            return false;
                        }
    );

    return true;
}
