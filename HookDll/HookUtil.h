#ifndef _H_HOOK_UTIL_
#define _H_HOOK_UTIL_

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <stdio.h>

#ifdef      __cplusplus
//#define DLLEXPORT extern "C" __declspec(dllexport)
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __declspec(dllexport)
#endif

const wchar_t* GetApplicationPath();
const wchar_t* GetApplicationDir();

void InitUtil();
void UninitUtil();

void OutputLastError(const wchar_t* errorInfo);
void OutputHookLog(const wchar_t* info);


void EnumAllModule(unsigned long processId, std::vector<MODULEENTRY32>& output);

#endif