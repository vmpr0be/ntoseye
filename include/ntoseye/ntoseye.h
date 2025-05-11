#ifndef _NTOSEYE_H_
#define _NTOSEYE_H_

#include <inttypes.h>

/*
 * to-do: these should be in a common file
 */
#define NTOSEYE_COMMAND_SUCCESS 0
#define NTOSEYE_COMMAND_INVALID_SYNTAX 1
#define NTOSEYE_COMMAND_INVALID_ARGUMENT 2
#define NTOSEYE_COMMAND_UNIMPLEMENTED 3

typedef void *NTProcess;
typedef int(*NTCallbackProc)(int argc, char **argv);

#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN extern
#endif

EXTERN NTProcess NT_GetCurrentProcess();

EXTERN int NT_RegisterCallback(NTCallbackProc proc, char *name);

EXTERN uint64_t NT_ProcessGetBaseAddress(NTProcess process);

#endif
