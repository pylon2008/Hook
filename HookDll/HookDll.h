#ifndef HOOK_DLL
#define HOOK_DLL

#include <windows.h>

#ifdef      __cplusplus
//#define DLLEXPORT extern "C" __declspec(dllexport)
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __declspec(dllexport)
#endif

//DLLEXPORT void InitHook(HWND hwnd);

//DLLEXPORT void UnInitHook();

//DLLEXPORT void GetWindowNameByHandle(HWND hwnd, wchar_t* dest);

#endif