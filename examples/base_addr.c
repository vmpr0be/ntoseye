#include "../include/ntoseye/ntoseye.h"
#include <stdio.h>

int print(int argc, char **argv)
{
    NTProcess process = NT_GetCurrentProcess();

    printf("%lx\n", NT_ProcessGetBaseAddress(process));

    return NTOSEYE_COMMAND_SUCCESS;
}

__attribute__((constructor))
void plugin_init()
{
    NT_RegisterCallback(print, "print_base_addr");
}
