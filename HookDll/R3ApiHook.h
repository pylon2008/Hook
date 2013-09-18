#ifndef _H_R3_API_HOOK_
#define _H_R3_API_HOOK_
#include "HookUtil.h"

#include <windows.h>

void R3ApiHookInit(HMODULE hModule);
void R3ApiHookUninit();

#endif