#ifndef _H_HOOK_UTIL_
#define _H_HOOK_UTIL_

#ifdef      __cplusplus
//#define DLLEXPORT extern "C" __declspec(dllexport)
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __declspec(dllexport)
#endif


void InitUtil();
void UninitUtil();

void OutputLastError(const wchar_t* errorInfo);
void OutputHookLog(const wchar_t* info);

#endif