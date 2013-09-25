#include "stdafx.h"
#include "R3ApiHook.h"
#include "HookUtil.h"
#include <stdio.h>

bool g_TimeProc = true;
bool g_IsTimeSetByHook = false;

#define HOOK_NEED_CHECK 0
#define HOOK_CAN_WRITE	1
#define HOOK_ONLY_READ	2

#define BUFFERLEN		7

typedef struct _tagApiHookStruct
{
	wchar_t*  lpszApiModuleName;
	LPSTR  lpszApiName;
	DWORD  dwApiOffset;
	LPVOID lpWinApiProc;
	BYTE   WinApiFiveByte[7];

	wchar_t*  lpszHookApiModuleName;
	LPSTR  lpszHookApiName;
	LPVOID lpHookApiProc;
	BYTE   HookApiFiveByte[7];

	HINSTANCE hInst;

	BYTE   WinApiBakByte[7];
}
APIHOOKSTRUCT, *LPAPIHOOKSTRUCT;

////////////////////////////////////////////////////////////////////////////////////////////////////
//#define HOOK_API_DLL_EXPORT	DLLEXPORT
#define HOOK_API_DLL_EXPORT
HOOK_API_DLL_EXPORT VOID WINAPI NHGetLocalTime(LPSYSTEMTIME lpSystemTime);
HOOK_API_DLL_EXPORT VOID WINAPI NHGetSystemTime(LPSYSTEMTIME lpSystemTime);
HOOK_API_DLL_EXPORT VOID WINAPI NHGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
HOOK_API_DLL_EXPORT BOOL WINAPI NHCreateProcessW(
									   __in_opt    LPCWSTR lpApplicationName,
									   __inout_opt LPWSTR lpCommandLine,
									   __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
									   __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
									   __in        BOOL bInheritHandles,
									   __in        DWORD dwCreationFlags,
									   __in_opt    LPVOID lpEnvironment,
									   __in_opt    LPCWSTR lpCurrentDirectory,
									   __in        LPSTARTUPINFOW lpStartupInfo,
									   __out       LPPROCESS_INFORMATION lpProcessInformation
									   );
HOOK_API_DLL_EXPORT BOOL WINAPI NHCreateProcessA(
									   __in_opt    LPCSTR lpApplicationName,
									   __inout_opt LPSTR lpCommandLine,
									   __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
									   __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
									   __in        BOOL bInheritHandles,
									   __in        DWORD dwCreationFlags,
									   __in_opt    LPVOID lpEnvironment,
									   __in_opt    LPSTR lpCurrentDirectory,
									   __in        LPSTARTUPINFOA lpStartupInfo,
									   __out       LPPROCESS_INFORMATION lpProcessInformation
									   );
HOOK_API_DLL_EXPORT HANDLE WINAPI NHCreateThread(
									   __in_opt  LPSECURITY_ATTRIBUTES lpThreadAttributes,
									   __in      SIZE_T dwStackSize,
									   __in      LPTHREAD_START_ROUTINE lpStartAddress,
									   __in_opt  LPVOID lpParameter,
									   __in      DWORD dwCreationFlags,
									   __out_opt LPDWORD lpThreadId
									   );
HOOK_API_DLL_EXPORT HANDLE WINAPI NHCreateFileW(
									  __in     LPCWSTR lpFileName,
									  __in     DWORD dwDesiredAccess,
									  __in     DWORD dwShareMode,
									  __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									  __in     DWORD dwCreationDisposition,
									  __in     DWORD dwFlagsAndAttributes,
									  __in_opt HANDLE hTemplateFile
									  );
HOOK_API_DLL_EXPORT HANDLE WINAPI NHCreateFileA(
									  __in     LPCSTR lpFileName,
									  __in     DWORD dwDesiredAccess,
									  __in     DWORD dwShareMode,
									  __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									  __in     DWORD dwCreationDisposition,
									  __in     DWORD dwFlagsAndAttributes,
									  __in_opt HANDLE hTemplateFile
									  );
HOOK_API_DLL_EXPORT HMODULE WINAPI NHLoadLibraryA(
										__in LPCSTR lpLibFileName
										);

namespace
{
	APIHOOKSTRUCT g_GetLocalTimeHook = {
		L"Kernel32.dll",
		"GetLocalTime",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHGetLocalTime",
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_GetSystemTimeHook = {
		L"Kernel32.dll",
		"GetSystemTime",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHGetSystemTime",
		NHGetSystemTime,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_GetSystemTimeAsFileTimeHook = {
		L"Kernel32.dll",
		"GetSystemTimeAsFileTime",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHGetSystemTimeAsFileTime",
		NHGetSystemTimeAsFileTime,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_CreateProcessWHook = {
		L"Kernel32.dll",
		"CreateProcessW",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHCreateProcessW",
		NHCreateProcessW,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_CreateProcessAHook = {
		L"Kernel32.dll",
		"CreateProcessA",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHCreateProcessA",
		NHCreateProcessA,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_CreateThreadHook = {
		L"Kernel32.dll",
		"CreateThread",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHCreateThread",
		NHCreateThread,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_CreateFileWHook = {
		L"Kernel32.dll",
		"CreateFileW",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHCreateFileW",
		NHCreateFileW,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_CreateFileAHook = {
		L"Kernel32.dll",
		"CreateFileA",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHCreateFileA",
		NHCreateFileA,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};

	APIHOOKSTRUCT g_LoadLibraryAHook = {
		L"Kernel32.dll",
		"LoadLibraryA",
		0,
		NULL,
		{0, 0, 0, 0, 0, 0, 0},
		NULL,
		"NHLoadLibraryA",
		NHLoadLibraryA,
		{0, 0, 0, 0, 0, 0, 0},
		0,
		{0XFF, 0X15, 0XFA, 0X13, 0XF3, 0XBF, 0X33}
	};
}
////////////////////////////////////////////////////////////////////////////////////////////////////
FARPROC WINAPI NHGetFuncAddress(HINSTANCE hInst, wchar_t* lpMod, char* lpFunc)
{
	HMODULE hMod;
	FARPROC procFunc;

	if (NULL != lpMod)
	{
		hMod=GetModuleHandle(lpMod);
		procFunc = GetProcAddress(hMod,lpFunc);
	}
	else
	{
		procFunc = GetProcAddress(hInst,lpFunc);

	}

	return  procFunc;
}

void MakeJMPCode(LPBYTE lpJMPCode, LPVOID lpCodePoint)
{
	BYTE temp;
	WORD wHiWord = HIWORD(lpCodePoint);
	WORD wLoWord = LOWORD(lpCodePoint);
	WORD wCS;

	_asm						// ȡ��ǰ�x����q
	{
		push ax;
		push cs;
		pop  ax;
		mov  wCS, ax;
		pop  ax;
	};

	lpJMPCode[0] = 0xea;		// ���� JMP ָ��ęC���a�q

	temp = LOBYTE(wLoWord);		// -------------------------
	lpJMPCode[1] = temp;
	temp = HIBYTE(wLoWord);
	lpJMPCode[2] = temp;		// �����ַ�q�ڃȴ��е����飻
	temp = LOBYTE(wHiWord);		// Point: 0x1234
	lpJMPCode[3] = temp;		// �ȴ棺 4321
	temp = HIBYTE(wHiWord);
	lpJMPCode[4] = temp;		// -------------------------

	temp = LOBYTE(wCS);			// �����x����q
	lpJMPCode[5] = temp;
	temp = HIBYTE(wCS);
	lpJMPCode[6] = temp;

	return;
}


void HookWin32Api(LPAPIHOOKSTRUCT lpApiHook, int nSysMemStatus)
{

	DWORD  dwReserved;
	DWORD  dwTemp;
	BYTE   bWin32Api[5];

	bWin32Api[0] = 0x00; 

	//TextOut(GetDC(GetActiveWindow()),2,15,"here",20);

	// ȡ�ñ��r�غ�����ַ�q
	if(lpApiHook->lpWinApiProc == NULL)
	{	
		lpApiHook->lpWinApiProc = (LPVOID)NHGetFuncAddress(lpApiHook->hInst, lpApiHook->lpszApiModuleName,lpApiHook->lpszApiName);
		if (lpApiHook->dwApiOffset != 0)
		{
			lpApiHook->lpWinApiProc = (LPVOID)((DWORD)lpApiHook->lpWinApiProc + lpApiHook->dwApiOffset);
		}
	}

	// ȡ�����������ַ�q
	if(lpApiHook->lpHookApiProc == NULL)
	{
		lpApiHook->lpHookApiProc = (LPVOID)NHGetFuncAddress(lpApiHook->hInst,
			lpApiHook->lpszHookApiModuleName,lpApiHook->lpszHookApiName);
	}

	// �γ� JMP ָ��q
	if (lpApiHook->HookApiFiveByte[0] == 0x00)
	{
		MakeJMPCode(lpApiHook->HookApiFiveByte, lpApiHook->lpHookApiProc);
	}

	if (!VirtualProtect(lpApiHook->lpWinApiProc, 16, PAGE_READWRITE,
		&dwReserved))
	{
		MessageBox(NULL, L"VirtualProtect-READWRITE", NULL, MB_OK);
		return;
	}

	if (nSysMemStatus == HOOK_NEED_CHECK)
	{
		memcpy(lpApiHook->lpWinApiProc, (LPVOID)lpApiHook->HookApiFiveByte,BUFFERLEN);
	}
	else
	{
		if (lpApiHook->WinApiFiveByte[0] == 0x00)			// �Д��Ƿ��ѽ��r�ةq
		{
			// ��q
			// ��� API �����^�傀�ֹ��q
			memcpy(lpApiHook->WinApiFiveByte,(LPVOID)lpApiHook->lpWinApiProc,BUFFERLEN);
			// �Д��Ƿ����}�r�ةq(���Д���ݵ��^�傀�ֹ��Ƿ���γɵ�JMPָ��)
			if (strncmp((const char*)lpApiHook->WinApiFiveByte, 
				(const char*)lpApiHook->HookApiFiveByte, BUFFERLEN) == 0)
			{
				// �֏͂�ݵ��ֹ��q
				memcpy(lpApiHook->WinApiFiveByte,(LPVOID)lpApiHook->WinApiBakByte,BUFFERLEN);
			}
		}
		else
		{
			// �ǩq
			memcpy(bWin32Api,(LPVOID)lpApiHook->lpWinApiProc,BUFFERLEN);
		}

		if (strncmp((const char*)bWin32Api, (const char*)lpApiHook->HookApiFiveByte,
			BUFFERLEN) != 0)
		{
			// �� JMP ָ������ API �������^�q
			memcpy(lpApiHook->lpWinApiProc, (LPVOID)lpApiHook->HookApiFiveByte,BUFFERLEN);
		}
	}

	if (!VirtualProtect(lpApiHook->lpWinApiProc, 16, dwReserved, &dwTemp))
	{
		MessageBox(NULL, L"VirtualProtect-RESTORE", NULL, MB_OK);
		return;
	}

}

void RestoreWin32Api(LPAPIHOOKSTRUCT lpApiHook, int nSysMemStatus)
{
	DWORD dwReserved;
	DWORD dwTemp;

	if (lpApiHook->lpWinApiProc == NULL)
		return;

	if (!VirtualProtect(lpApiHook->lpWinApiProc, 16, PAGE_READWRITE,
		&dwReserved))
	{
		MessageBox(NULL, L"VirtualProtect-READWRITE", NULL, MB_OK);
		return;
	}
	memcpy(lpApiHook->lpWinApiProc,(LPVOID)lpApiHook->WinApiFiveByte,BUFFERLEN);
	if (!VirtualProtect(lpApiHook->lpWinApiProc, 16, dwReserved, &dwTemp))
	{
		MessageBox(NULL, L"VirtualProtect-RESTORE", NULL, MB_OK);
		return;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void TimeAdd1Year(SYSTEMTIME& time)
{
	SYSTEMTIME backupTime;
	::GetSystemTime(&backupTime);

	time.wYear += 1;
	::SetSystemTime(&time);
	::GetSystemTime(&time);

	::SetSystemTime(&backupTime);
}

void TimeSub1Year(SYSTEMTIME& time)
{
	return;
	g_TimeProc = false;
	/*SYSTEMTIME backupTime;
	::GetLocalTime(&backupTime);

	time.wYear -= 1;
	::SetLocalTime(&time);
	::GetLocalTime(&time);

	::SetLocalTime(&backupTime);*/

	SYSTEMTIME backupTime;
	::GetSystemTime(&backupTime);

	time.wYear -= 1;
	::SetSystemTime(&time);
	::GetSystemTime(&time);

	//TimeAdd1Year(backupTime);
	::SetSystemTime(&backupTime);


	/*LONG bias = -60 * 24 * 365*10; 
	TIME_ZONE_INFORMATION DEFAULT_TIME_ZONE_INFORMATION = {-bias};
	SystemTimeToTzSpecificLocalTime(&DEFAULT_TIME_ZONE_INFORMATION, &time, &time);*/
	g_TimeProc = true;
}

HOOK_API_DLL_EXPORT VOID WINAPI NHGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));


	// restore
	RestoreWin32Api(&g_GetLocalTimeHook, HOOK_NEED_CHECK);

	::GetLocalTime(lpSystemTime);
	if (g_TimeProc == true)
	{
		TimeSub1Year(*lpSystemTime);
	}

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHGetLocalTime: %s,%d,%d,%d,%d,%d,%d,%d,%d,%d\r\n", hmod, returnAddr, lpSystemTime->wYear, lpSystemTime->wMonth,
		lpSystemTime->wDay, lpSystemTime->wDayOfWeek,lpSystemTime->wHour, lpSystemTime->wMinute, lpSystemTime->wSecond, lpSystemTime->wMilliseconds);
	OutputHookLog(buf);

	//
	HookWin32Api(&g_GetLocalTimeHook, HOOK_NEED_CHECK);
}

HOOK_API_DLL_EXPORT VOID WINAPI NHGetSystemTime(LPSYSTEMTIME lpSystemTime)
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));

	// restore
	RestoreWin32Api(&g_GetSystemTimeHook, HOOK_NEED_CHECK);

	::GetSystemTime(lpSystemTime);
	if (g_TimeProc == true)
	{
		TimeSub1Year(*lpSystemTime);
	}

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHGetSystemTime: %s,%d,%d,%d,%d,%d,%d,%d,%d,%d\r\n", modName, returnAddr, lpSystemTime->wYear, lpSystemTime->wMonth,
		lpSystemTime->wDay, lpSystemTime->wDayOfWeek,lpSystemTime->wHour, lpSystemTime->wMinute, lpSystemTime->wSecond, lpSystemTime->wMilliseconds);
	OutputHookLog(buf);

	//
	HookWin32Api(&g_GetSystemTimeHook, HOOK_NEED_CHECK);
}

void HookResettimeCallBack(void* parm)
{
	::Sleep(3000);
	if (g_IsTimeSetByHook == true)
	{
		//g_IsTimeSetByHook = false;
		SYSTEMTIME time;
		::GetSystemTime(&time);
		time.wYear += 1;
		::SetSystemTime(&time);
		OutputHookLog(L"reset time\r\n");
	}
}

HOOK_API_DLL_EXPORT VOID WINAPI NHGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));

	// restore
	RestoreWin32Api(&g_GetSystemTimeAsFileTimeHook, HOOK_NEED_CHECK);

	if (g_IsTimeSetByHook == false)
	{
		g_IsTimeSetByHook = true;
		SYSTEMTIME time;
		::GetSystemTime(&time);
		time.wYear -= 1;
		::SetSystemTime(&time);
		::CreateThread(0,0,(LPTHREAD_START_ROUTINE)HookResettimeCallBack,0,0,0);
		OutputHookLog(L"set time\r\n");
	}

	SYSTEMTIME systime;
	::GetSystemTime(&systime);
	//TimeSub1Year(systime);
	LPSYSTEMTIME lpSystemTime = &systime;

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHGetSystemTimeAsFileTime: %s,%d,%d,%d,%d,%d,%d,%d,%d,%d\r\n", modName, returnAddr, lpSystemTime->wYear, lpSystemTime->wMonth,
		lpSystemTime->wDay, lpSystemTime->wDayOfWeek,lpSystemTime->wHour, lpSystemTime->wMinute, lpSystemTime->wSecond, lpSystemTime->wMilliseconds);
	OutputHookLog(buf);

	::SystemTimeToFileTime(&systime, lpSystemTimeAsFileTime);

	//
	HookWin32Api(&g_GetSystemTimeAsFileTimeHook, HOOK_NEED_CHECK);
}

HOOK_API_DLL_EXPORT BOOL WINAPI NHCreateProcessW(
									   __in_opt    LPCWSTR lpApplicationName,
									   __inout_opt LPWSTR lpCommandLine,
									   __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
									   __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
									   __in        BOOL bInheritHandles,
									   __in        DWORD dwCreationFlags,
									   __in_opt    LPVOID lpEnvironment,
									   __in_opt    LPCWSTR lpCurrentDirectory,
									   __in        LPSTARTUPINFOW lpStartupInfo,
									   __out       LPPROCESS_INFORMATION lpProcessInformation
									   )
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));

	// restore
	RestoreWin32Api(&g_CreateProcessWHook, HOOK_NEED_CHECK);

	LPPROCESS_INFORMATION info = lpProcessInformation;
	PROCESS_INFORMATION infoStuct;
	bool rtnInfo = true;
	if (info == 0)
	{
		rtnInfo = false;
		info = &infoStuct;
	}
	BOOL isCreate = ::CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo, info);
	//::Sleep(1000);

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHCreateProcessW: %s,%d,", modName, returnAddr);
	// lpApplicationName
	if (lpApplicationName != 0)
	{
		swprintf(buf+wcslen(buf), L"%s,", lpApplicationName);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpApplicationName);
	}

	// lpCommandLine
	if (lpCommandLine != 0)
	{
		swprintf(buf+wcslen(buf), L"%s,", lpCommandLine);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpCommandLine);
	}

	// lpCurrentDirectory
	if (lpCurrentDirectory != 0)
	{
		swprintf(buf+wcslen(buf), L"%s,", lpCurrentDirectory);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpCurrentDirectory);
	}

	// lpProcessAttributes
	if (lpProcessAttributes != 0)
	{
		swprintf(buf+wcslen(buf), L"(%d,%p,%d),", lpProcessAttributes->bInheritHandle, lpProcessAttributes->lpSecurityDescriptor, lpProcessAttributes->nLength);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpProcessAttributes);
	}

	// lpThreadAttributes
	if (lpThreadAttributes != 0)
	{
		swprintf(buf+wcslen(buf), L"(%d,%p,%d),", lpThreadAttributes->bInheritHandle, lpThreadAttributes->lpSecurityDescriptor, lpThreadAttributes->nLength);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpThreadAttributes);
	}
	swprintf(buf+wcslen(buf), L"%d,%d,%p,", bInheritHandles, dwCreationFlags, lpEnvironment);
	swprintf(buf+wcslen(buf), L"(%d,%p,%p,%d,%d),", rtnInfo, info->hProcess, info->hThread, info->dwProcessId, info->dwThreadId);
	swprintf(buf+wcslen(buf), L"%s", L"\r\n");

	OutputHookLog(buf);

	//ProcessInjection(info->dwProcessId);

	//
	HookWin32Api(&g_CreateProcessWHook, HOOK_NEED_CHECK);

	return isCreate;
}

HOOK_API_DLL_EXPORT BOOL WINAPI NHCreateProcessA(
									   __in_opt    LPCSTR lpApplicationName,
									   __inout_opt LPSTR lpCommandLine,
									   __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
									   __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
									   __in        BOOL bInheritHandles,
									   __in        DWORD dwCreationFlags,
									   __in_opt    LPVOID lpEnvironment,
									   __in_opt    LPSTR lpCurrentDirectory,
									   __in        LPSTARTUPINFOA lpStartupInfo,
									   __out       LPPROCESS_INFORMATION lpProcessInformation
									   )
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));

	// restore
	RestoreWin32Api(&g_CreateProcessAHook, HOOK_NEED_CHECK);

	LPPROCESS_INFORMATION info = lpProcessInformation;
	PROCESS_INFORMATION infoStuct;
	bool rtnInfo = true;
	if (info == 0)
	{
		rtnInfo = false;
		info = &infoStuct;
	}
	BOOL isCreate = ::CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment, lpCurrentDirectory, lpStartupInfo, info);
	//::Sleep(1000);

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHCreateProcessA: %s,%d,", modName, returnAddr);
	// lpApplicationName
	if (lpApplicationName != 0)
	{
		wchar_t tmpbuf[4096] = {0};
		MultiByteToWideChar(CP_ACP, NULL, lpApplicationName, -1, tmpbuf, sizeof(tmpbuf)/sizeof(wchar_t));
		swprintf(buf+wcslen(buf), L"%s,", tmpbuf);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpApplicationName);
	}

	// lpCommandLine
	if (lpCommandLine != 0)
	{
		wchar_t tmpbuf[4096] = {0};
		MultiByteToWideChar(CP_ACP, NULL, lpCommandLine, -1, tmpbuf, sizeof(tmpbuf)/sizeof(wchar_t));
		swprintf(buf+wcslen(buf), L"%s,", tmpbuf);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpCommandLine);
	}

	// lpCurrentDirectory
	if (lpCurrentDirectory != 0)
	{
		wchar_t tmpbuf[4096] = {0};
		MultiByteToWideChar(CP_ACP, NULL, lpCurrentDirectory, -1, tmpbuf, sizeof(tmpbuf)/sizeof(wchar_t));
		swprintf(buf+wcslen(buf), L"%s,", tmpbuf);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpCurrentDirectory);
	}

	// lpProcessAttributes
	if (lpProcessAttributes != 0)
	{
		swprintf(buf+wcslen(buf), L"(%d,%p,%d),", lpProcessAttributes->bInheritHandle, lpProcessAttributes->lpSecurityDescriptor, lpProcessAttributes->nLength);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpProcessAttributes);
	}

	// lpThreadAttributes
	if (lpThreadAttributes != 0)
	{
		swprintf(buf+wcslen(buf), L"(%d,%p,%d),", lpThreadAttributes->bInheritHandle, lpThreadAttributes->lpSecurityDescriptor, lpThreadAttributes->nLength);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpThreadAttributes);
	}
	swprintf(buf+wcslen(buf), L"%d,%d,%p,", bInheritHandles, dwCreationFlags, lpEnvironment);
	swprintf(buf+wcslen(buf), L"(%d,%p,%p,%d,%d),", rtnInfo, info->hProcess, info->hThread, info->dwProcessId, info->dwThreadId);
	swprintf(buf+wcslen(buf), L"%s", L"\r\n");

	OutputHookLog(buf);

	//ProcessInjection(info->dwProcessId);

	//
	HookWin32Api(&g_CreateProcessAHook, HOOK_NEED_CHECK);

	return isCreate;
}

HOOK_API_DLL_EXPORT HANDLE WINAPI NHCreateThread(
									   __in_opt  LPSECURITY_ATTRIBUTES lpThreadAttributes,
									   __in      SIZE_T dwStackSize,
									   __in      LPTHREAD_START_ROUTINE lpStartAddress,
									   __in_opt  LPVOID lpParameter,
									   __in      DWORD dwCreationFlags,
									   __out_opt LPDWORD lpThreadId
									   )
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));

	// restore
	RestoreWin32Api(&g_CreateThreadHook, HOOK_NEED_CHECK);

	HANDLE threadHandle = ::CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHCreateThread: %s,%d,", modName, returnAddr);

	swprintf(buf+wcslen(buf), L"%d,%p,%d,%d,", dwStackSize, lpParameter, dwCreationFlags, lpStartAddress);

	// lpThreadAttributes
	if (lpThreadAttributes != 0)
	{
		swprintf(buf+wcslen(buf), L"%d,%p,%d", lpThreadAttributes->nLength, lpThreadAttributes->lpSecurityDescriptor, lpThreadAttributes->bInheritHandle);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p,", lpThreadAttributes);
	}

	// lpThreadId
	if (lpThreadId != 0)
	{
		swprintf(buf+wcslen(buf), L"%d", *lpThreadId);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p", lpThreadId);
	}
	swprintf(buf+wcslen(buf), L"%s", L"\r\n");

	OutputHookLog(buf);

	//
	HookWin32Api(&g_CreateThreadHook, HOOK_NEED_CHECK);

	return threadHandle;
}

HOOK_API_DLL_EXPORT HANDLE WINAPI NHCreateFileW(
									  __in     LPCWSTR lpFileName,
									  __in     DWORD dwDesiredAccess,
									  __in     DWORD dwShareMode,
									  __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									  __in     DWORD dwCreationDisposition,
									  __in     DWORD dwFlagsAndAttributes,
									  __in_opt HANDLE hTemplateFile
									  )
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));


	// restore
	RestoreWin32Api(&g_CreateFileWHook, HOOK_NEED_CHECK);


	HANDLE file = ::CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHCreateFileW: %s,%d,", modName, returnAddr);
	swprintf(buf+wcslen(buf), L"%s,%d,%d,%d,%d,%p,", lpFileName, dwDesiredAccess, 
		dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );

	// lpThreadId
	if (lpSecurityAttributes != 0)
	{
		swprintf(buf+wcslen(buf), L"%d,%p,%d,", lpSecurityAttributes->nLength, lpSecurityAttributes->lpSecurityDescriptor, lpSecurityAttributes->bInheritHandle);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p", lpSecurityAttributes);
	}
	swprintf(buf+wcslen(buf), L"%s", L"\r\n");

	OutputHookLog(buf);

	//
	HookWin32Api(&g_CreateFileWHook, HOOK_NEED_CHECK);

	return file;
}

HOOK_API_DLL_EXPORT HANDLE WINAPI NHCreateFileA(
									  __in     LPCSTR lpFileName,
									  __in     DWORD dwDesiredAccess,
									  __in     DWORD dwShareMode,
									  __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
									  __in     DWORD dwCreationDisposition,
									  __in     DWORD dwFlagsAndAttributes,
									  __in_opt HANDLE hTemplateFile
									  )
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));

	wchar_t tmpbuf[4096] = {0};
	MultiByteToWideChar(CP_ACP, NULL, lpFileName, -1, tmpbuf, sizeof(tmpbuf)/sizeof(wchar_t));

	// restore
	RestoreWin32Api(&g_CreateFileAHook, HOOK_NEED_CHECK);

	char realCreateFile[1024] = {0};
	strcpy(realCreateFile, lpFileName);
	//int delta = strcmp(modName, lpFileName);
	//int delta = wcscmp(modName, tmpbuf);
	//if (delta == 0)
	if( strstr(realCreateFile, "_�ƽ�") != 0 )
	{
		char* exe = strstr(realCreateFile, ".exe");
		memcpy(exe-5, ".exe", 5);
	}

	HANDLE file = ::CreateFileA(realCreateFile, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
		dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	wchar_t tmpbuf2[4096] = {0};
	MultiByteToWideChar(CP_ACP, NULL, realCreateFile, -1, tmpbuf2, sizeof(tmpbuf2)/sizeof(wchar_t));
	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHCreateFileA: %s,%d,", modName, returnAddr);
	swprintf(buf+wcslen(buf), L"%s,%s,%d,%d,%d,%d,%p,", tmpbuf, tmpbuf2, dwDesiredAccess, 
		dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );

	// lpThreadId
	if (lpSecurityAttributes != 0)
	{
		swprintf(buf+wcslen(buf), L"%d,%p,%d,", lpSecurityAttributes->nLength, lpSecurityAttributes->lpSecurityDescriptor, lpSecurityAttributes->bInheritHandle);
	}
	else
	{
		swprintf(buf+wcslen(buf), L"%p", lpSecurityAttributes);
	}
	swprintf(buf+wcslen(buf), L"%s", L"\r\n");

	OutputHookLog(buf);

	//
	HookWin32Api(&g_CreateFileAHook, HOOK_NEED_CHECK);

	/*static unsigned long g_CreateFileTime = 0;
	g_CreateFileTime ++;
	if (g_CreateFileTime == 11)
	{
		void RepairR3ApiIAT();
		RepairR3ApiIAT();
	}*/

	return file;
}

HOOK_API_DLL_EXPORT HMODULE WINAPI NHLoadLibraryA(
			   __in LPCSTR lpLibFileName
			   )
{
	DWORD returnAddr = 0;
	__asm
	{
		MOV EAX,DWORD PTR SS:[EBP+4]
		MOV returnAddr,EAX
	}
	HMODULE hmod = 0;
	::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)returnAddr, &hmod);
	wchar_t modName[1024] = {0};
	::GetModuleFileNameW(hmod, modName, sizeof(modName));

	wchar_t tmpbuf[4096] = {0};
	MultiByteToWideChar(CP_ACP, NULL, lpLibFileName, -1, tmpbuf, sizeof(tmpbuf)/sizeof(wchar_t));

	// restore
	RestoreWin32Api(&g_LoadLibraryAHook, HOOK_NEED_CHECK);

	HMODULE mod = ::LoadLibraryA(lpLibFileName);

	wchar_t buf[1024] = {0};
	swprintf(buf, L"NHLoadLibraryA: %s,%d,%s\r\n", modName, returnAddr, tmpbuf);
	OutputHookLog(buf);

	//
	HookWin32Api(&g_LoadLibraryAHook, HOOK_NEED_CHECK);
	return mod;
}

//////////////////////////////////////////////////////////////////////////////////
void R3ApiHookInit(HMODULE hModule)
{
	g_GetLocalTimeHook.hInst = hModule;
	g_GetSystemTimeHook.hInst = hModule;
	g_GetSystemTimeAsFileTimeHook.hInst = hModule;
	g_CreateProcessWHook.hInst = hModule;
	g_CreateProcessAHook.hInst = hModule;
	g_CreateThreadHook.hInst = hModule;
	g_CreateFileWHook.hInst = hModule;
	g_CreateFileAHook.hInst = hModule;
	g_LoadLibraryAHook.hInst = hModule;

	//HookWin32Api(&g_GetLocalTimeHook, HOOK_CAN_WRITE);
	//HookWin32Api(&g_GetSystemTimeHook, HOOK_CAN_WRITE);
	//HookWin32Api(&g_GetSystemTimeAsFileTimeHook, HOOK_CAN_WRITE);

	/*HookWin32Api(&g_CreateProcessWHook, HOOK_CAN_WRITE);
	HookWin32Api(&g_CreateProcessAHook, HOOK_CAN_WRITE);
	HookWin32Api(&g_CreateThreadHook, HOOK_CAN_WRITE);
	HookWin32Api(&g_CreateFileWHook, HOOK_CAN_WRITE);*/

	//HookWin32Api(&g_CreateFileAHook, HOOK_CAN_WRITE);
	HookWin32Api(&g_LoadLibraryAHook, HOOK_CAN_WRITE);
}

void R3ApiHookUninit()
{
	//RestoreWin32Api(&g_GetLocalTimeHook, HOOK_NEED_CHECK);
	//RestoreWin32Api(&g_GetSystemTimeHook, HOOK_NEED_CHECK);
	//RestoreWin32Api(&g_GetSystemTimeAsFileTimeHook, HOOK_NEED_CHECK);

	/*RestoreWin32Api(&g_CreateProcessWHook, HOOK_NEED_CHECK);
	RestoreWin32Api(&g_CreateProcessAHook, HOOK_NEED_CHECK);
	RestoreWin32Api(&g_CreateThreadHook, HOOK_NEED_CHECK);
	RestoreWin32Api(&g_CreateFileWHook, HOOK_NEED_CHECK);*/

	//RestoreWin32Api(&g_CreateFileAHook, HOOK_NEED_CHECK);
	RestoreWin32Api(&g_LoadLibraryAHook, HOOK_NEED_CHECK);
}