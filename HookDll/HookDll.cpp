// HookDll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "HookDll.h"
#include <TlHelp32.h>
#include <stdio.h>
#include <algorithm>
//#include <string.h>

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#pragma data_seg(".data")
HHOOK		g_hHookMouse				= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookKeybord				= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookKeybordLL			= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookGetMessage			= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookCallWndProc			= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookCBT					= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookMouseLL				= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookShell				= NULL;	// 安装的鼠标钩子句柄
HHOOK		g_hHookJournalRecord		= NULL;	// 安装的鼠标钩子句柄

HWND		g_hChildren[4096] = {0};
long		g_numChildren = 0;

FILE*		g_HookLog			= NULL;
HINSTANCE	g_hinstDll	= NULL; // DLL实例句柄
HWND		g_hWndTag	= NULL;	//注入的EXE窗体句柄
#pragma data_seg()
//#pragma comment(linker, "/SECTION:.Hookdata,RWS")


//////////////////////////////////////////////////////////////////////////////////////
DLLEXPORT void OutputLastError(const wchar_t* errorInfo)
{
	DWORD lastError = GetLastError();
	wchar_t buf[1024] = {0};
	swprintf(buf, L"%s,LastError:%d", errorInfo, lastError);
	MessageBox(0,buf,0,0);
}

DLLEXPORT void OutputHookLog(const wchar_t* info)
{
	if (g_HookLog!=NULL)
	{
		char cbuf[1024] = {0};
		WideCharToMultiByte(CP_ACP, NULL,
			info, -1,
			cbuf,
			sizeof(cbuf),NULL,NULL);
		fprintf(g_HookLog, "%d,%d,%s", ::GetCurrentProcessId(), ::GetCurrentThreadId(), cbuf);
	}
}

DLLEXPORT BOOL CALLBACK EnumChildWindowsProc( HWND hWnd, LPARAM lParam )
{
	g_hChildren[g_numChildren++] = hWnd;
	return TRUE;
}

DLLEXPORT void GetAllChildrenWnd(HWND hwnd)
{
	memset(g_hChildren, 0, sizeof(g_hChildren));
	g_numChildren = 0;
	g_hChildren[g_numChildren++] = hwnd;
	EnumChildWindows(g_hWndTag, EnumChildWindowsProc,0);
}

DLLEXPORT bool FilterWnd(HWND hwnd)
{
	return true;
	HWND* findResult = std::find(&g_hChildren[0], &g_hChildren[g_numChildren], hwnd);
	return findResult==&g_hChildren[g_numChildren];
}

DLLEXPORT bool FilterCode(int nCode)
{
	return true;
	return nCode>=0;
}

DLLEXPORT void GetWindowNameByHandle(HWND hwnd, wchar_t* dest, int destSize)
{
	//HWND children = hwnd;
	//HWND parentWnd = children;
	//while (1)
	//{
	//	parentWnd = ::GetParent(children);
	//	if (parentWnd == NULL)
	//	{
	//		break;
	//	}
	//	children = parentWnd;
	//}
	//wchar_t childrenName[256] = {0};
	//wchar_t parentName[256] = {0};
	//::GetWindowTextW(hwnd, childrenName, sizeof(childrenName));
	//::GetWindowTextW(children, parentName, sizeof(parentName));
	//swprintf(dest, L"%s-%s", childrenName, parentName);
	//return;

	DWORD dwProcId;
	DWORD theadID = ::GetWindowThreadProcessId(hwnd, &dwProcId);

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof( PROCESSENTRY32 );
	// 创建快照句柄
	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// 先搜索系统中第一个进程的信息
	::Process32First(hSnapshot, &pe);
	// 下面对系统中的所有进程进行枚举，并保存其信息
	do
	{
		if (pe.th32ProcessID == dwProcId)
		{
			swprintf(dest, L"%d-%d-%s",dwProcId, theadID, pe.szExeFile);
			//memcpy(dest, pe.szExeFile, wcslen(pe.szExeFile)*sizeof(wchar_t));
			break;
		}
	}
	while (Process32Next(hSnapshot, &pe));
	DWORD lastError = ::GetLastError();
	if (lastError == ERROR_NO_MORE_FILES)
	{
		int a = 0;
		a = 0;
	}
	// 关闭快照句柄
	CloseHandle(hSnapshot);
}

DLLEXPORT void EnumAllWindowSnapshot()
{
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof( PROCESSENTRY32 );
	// 创建快照句柄
	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// 先搜索系统中第一个进程的信息
	::Process32First(hSnapshot, &pe);
	// 下面对系统中的所有进程进行枚举，并保存其信息
	do
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"%d,%d,%d,%d,%d,%d,%d,%d,%d,%s\r\n", pe.cntThreads, pe.cntUsage, pe.dwFlags, pe.dwSize, pe.pcPriClassBase, 
			pe.th32DefaultHeapID, pe.th32ModuleID,pe.th32ParentProcessID, pe.th32ProcessID, pe.szExeFile);
		OutputHookLog(buf);
	}
	while (Process32Next(hSnapshot, &pe));
	DWORD lastError = ::GetLastError();
	if (lastError == ERROR_NO_MORE_FILES)
	{
		int a = 0;
		a = 0;
	}
	// 关闭快照句柄
	CloseHandle(hSnapshot);
}
//////////////////////////////////////////////////////////////////////////////////////


DLLEXPORT LRESULT CALLBACK MouseProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		LPMOUSEHOOKSTRUCT msg = (LPMOUSEHOOKSTRUCT)lParam;
		wchar_t wndName[256]={0};
		GetWindowNameByHandle(msg->hwnd, wndName, sizeof(wndName));
		wchar_t fileName[256] = {0};
		::GetModuleFileName(0, fileName, sizeof(fileName));

		wchar_t buf[1024] = {0};
		swprintf(buf,L"MouseProc: %s,%s,%d,%d,%d,%d,%d\r\n", wndName, fileName, 
			msg->dwExtraInfo, msg->hwnd, msg->pt.x, msg->pt.y, msg->wHitTestCode);
		OutputHookLog(buf);
	}
	return CallNextHookEx(g_hHookMouse, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK KeyboardProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		wchar_t buf[1024] = {0};
		swprintf(buf,L"KeyboardProc: %d,%d,%d\r\n", nCode, wParam, lParam);
		OutputHookLog(buf);
	}
	return CallNextHookEx(g_hHookKeybord, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK KeyboardLLProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		LPKBDLLHOOKSTRUCT kb;
		kb = (LPKBDLLHOOKSTRUCT)lParam;
		wchar_t fileName[256] = {0};
		::GetModuleFileName(0, fileName, sizeof(fileName));
		wchar_t buf[1024] = {0};
		swprintf(buf,L"KeyboardLLProc: %s,%d,%d,%d,%d,%d\r\n", fileName, kb->dwExtraInfo, kb->flags, kb->scanCode,kb->time,kb->vkCode);
		OutputHookLog(buf);
	}
	return CallNextHookEx(g_hHookKeybordLL, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK GetMessageProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		LPMSG pMsg = (LPMSG)lParam;	
		if(NULL != pMsg->hwnd)
		{
			wchar_t wndName[256]={0};
			GetWindowNameByHandle(pMsg->hwnd, wndName, sizeof(wndName));
			wchar_t fileName[256] = {0};
			::GetModuleFileName(0, fileName, sizeof(fileName));
			wchar_t buf[1024] = {0};
			swprintf(buf,L"GetMessageProc: %s,%s,%d,%d,%d,%d,%d,%d,%d\r\n", wndName, fileName, pMsg->hwnd, pMsg->message, 
				pMsg->lParam, pMsg->wParam, pMsg->pt.x, pMsg->pt.y,
				pMsg->time);
			OutputHookLog(buf);
		}
	}

	return CallNextHookEx(g_hHookGetMessage, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK CallWndProcProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		PCWPSTRUCT msg = (PCWPSTRUCT)lParam;
		if (msg->hwnd != NULL)
		{
			if ( FilterWnd(msg->hwnd) )
			{
				wchar_t wndName[256]={0};
				GetWindowNameByHandle(msg->hwnd, wndName, sizeof(wndName));
				wchar_t fileName[256] = {0};
				::GetModuleFileName(0, fileName, sizeof(fileName));
				wchar_t buf[1024] = {0};
				swprintf(buf,L"CallWndProcProc: %s,%s,%d,%d,%d,%d\r\n", wndName, fileName, msg->hwnd, msg->message, 
					msg->lParam, msg->wParam);
				OutputHookLog(buf);
			}
		}
	}
	return CallNextHookEx(g_hHookCallWndProc, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK MouseLLProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		LPMSLLHOOKSTRUCT cbt;
		cbt = (LPMSLLHOOKSTRUCT)lParam;
		wchar_t fileName[256] = {0};
		::GetModuleFileName(0, fileName, sizeof(fileName));
		wchar_t buf[1024] = {0};
		swprintf(buf,L"MouseLLProc: %s,%d,%d,%d,%d,%d,%d\r\n", fileName, cbt->pt.x, cbt->pt.y,
			cbt->dwExtraInfo, cbt->flags, cbt->mouseData, cbt->time);
		OutputHookLog(buf);
	}
	return CallNextHookEx(g_hHookMouseLL, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK CBTProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		LPCBTACTIVATESTRUCT cbt;
		cbt = (LPCBTACTIVATESTRUCT)lParam;
		if (cbt->hWndActive != NULL)
		{
			if ( FilterWnd(cbt->hWndActive) )
			{
				wchar_t wndName[256]={0};
				GetWindowNameByHandle(cbt->hWndActive, wndName, sizeof(wndName));
				wchar_t fileName[256] = {0};
				::GetModuleFileName(0, fileName, sizeof(fileName));
				wchar_t buf[1024] = {0};
				swprintf(buf,L"CBTProc: %s,%s,%d,%d\r\n", wndName, fileName, cbt->fMouse, cbt->hWndActive);
				OutputHookLog(buf);
			}
		}
	}
	
	return CallNextHookEx(g_hHookCBT, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK ShellProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		wchar_t wndName[256] = {0};
		if(nCode == HSHELL_WINDOWACTIVATED || nCode == HSHELL_LANGUAGE)
		{
			GetWindowNameByHandle((HWND)wParam, wndName, sizeof(wndName));
		}
		wchar_t fileName[256] = {0};
		::GetModuleFileName(0, fileName, sizeof(fileName));
		wchar_t buf[1024] = {0};
		swprintf(buf,L"ShellProc: %s,%s,%d,%d,%d\r\n", fileName, wndName, nCode, wParam, lParam);
		OutputHookLog(buf);
	}

	return CallNextHookEx(g_hHookShell, nCode, wParam, lParam);
}

DLLEXPORT LRESULT CALLBACK JournalRecordProc(int nCode,WPARAM wParam,LPARAM lParam)
{
	if ( FilterCode(nCode) )
	{
		PEVENTMSGMSG msg = (PEVENTMSGMSG)lParam;
		if (msg->hwnd != NULL)
		{
			if ( FilterWnd(msg->hwnd) )
			{
				wchar_t wndName[256]={0};
				GetWindowNameByHandle(msg->hwnd, wndName, sizeof(wndName));
				wchar_t fileName[256] = {0};
				::GetModuleFileName(0, fileName, sizeof(fileName));
				wchar_t buf[1024] = {0};
				swprintf(buf,L"JournalRecordProc: %s,%s,%d,%d,%d,%d,%d\r\n", wndName, fileName, msg->hwnd, msg->message, 
					msg->paramL, msg->paramH, msg->time);
				OutputHookLog(buf);
			}
		}
	}

	return CallNextHookEx(g_hHookJournalRecord, nCode, wParam, lParam);
}

DLLEXPORT void InitHook(HWND hwnd)
{
	g_hWndTag = hwnd;
	GetAllChildrenWnd(g_hWndTag);
	if (g_HookLog == NULL)
	{
		g_HookLog = fopen("d://hooklog.txt", "w+b");
	}
	
	HINSTANCE hmod = GetModuleHandle(L"HookDll");
	DWORD dwThreadId = 0;
	wchar_t* targetWndName = L"Error Lookup";
	HWND targetHwnd = ::FindWindow(0, targetWndName);
	DWORD dwProcId;
	DWORD theadID = ::GetWindowThreadProcessId(targetHwnd, &dwProcId);
	wchar_t buf[1024] = {0};
	swprintf(buf, L"%s,%d,%d,%d", targetWndName, targetHwnd, dwProcId, theadID);
	OutputHookLog(buf);
	dwThreadId = theadID;
	dwThreadId = 0;

	g_hHookMouse = SetWindowsHookEx(WH_MOUSE, MouseProc, hmod,dwThreadId);
	if (g_hHookMouse == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookMouse error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookKeybord = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, hmod,dwThreadId);
	if (g_hHookKeybord == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookKeybord error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookKeybordLL = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardLLProc, hmod,dwThreadId);
	if (g_hHookKeybordLL == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookKeybordLL error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookGetMessage = SetWindowsHookEx(WH_GETMESSAGE, GetMessageProc, hmod,dwThreadId);
	if (g_hHookGetMessage == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookGetMessage error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookCallWndProc = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProcProc, hmod,dwThreadId);
	if (g_hHookCallWndProc == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookCallWndProc error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookCBT = SetWindowsHookEx(WH_CBT, CBTProc, hmod,dwThreadId);
	if (g_hHookCBT == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookCBT error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookMouseLL = SetWindowsHookEx(WH_MOUSE_LL, MouseLLProc, hmod,dwThreadId);
	if (g_hHookMouseLL == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookMouseLL error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookShell= SetWindowsHookEx(WH_SHELL, ShellProc, hmod,dwThreadId);
	if (g_hHookShell == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookShell error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}

	g_hHookJournalRecord= SetWindowsHookEx(WH_JOURNALRECORD, JournalRecordProc, hmod,dwThreadId);
	if (g_hHookJournalRecord == NULL)
	{
		wchar_t buf[256] = {0};
		swprintf(buf, L"SetWindowsHookEx g_hHookJournalRecord error %p,%d", hmod, dwThreadId);
		OutputLastError(buf);
	}
}

DLLEXPORT void UnInitHook()
{
	EnumAllWindowSnapshot();

	if (g_HookLog!=NULL)
	{
		fclose(g_HookLog);
	}

	if (g_hHookMouse != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookMouse))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookMouse error %p", g_hHookMouse);
			OutputLastError(buf);
		}
		else
		{
			g_hHookMouse = NULL;
		}
	}

	if (g_hHookKeybord != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookKeybord))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookKeybord error %p", g_hHookKeybord);
			OutputLastError(buf);
		}
		else
		{
			g_hHookKeybord = NULL;
		}
	}

	if (g_hHookKeybordLL != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookKeybordLL))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookKeybordLL error %p", g_hHookKeybordLL);
			OutputLastError(buf);
		}
		else
		{
			g_hHookKeybordLL = NULL;
		}
	}

	if (g_hHookGetMessage != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookGetMessage))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookGetMessage error %p", g_hHookGetMessage);
			OutputLastError(buf);
		}
		else
		{
			g_hHookGetMessage = NULL;
		}
	}

	if (g_hHookCallWndProc != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookCallWndProc))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookCallWndProc error %p", g_hHookCallWndProc);
			OutputLastError(buf);
		}
		else
		{
			g_hHookCallWndProc = NULL;
		}
	}

	if (g_hHookCBT != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookCBT))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookCBT error %p", g_hHookCBT);
			OutputLastError(buf);
		}
		else
		{
			g_hHookCBT = NULL;
		}
	}

	if (g_hHookMouseLL != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookMouseLL))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookMouseLL error %p", g_hHookMouseLL);
			OutputLastError(buf);
		}
		else
		{
			g_hHookMouseLL = NULL;
		}
	}

	if (g_hHookShell != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookShell))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookShell error %p", g_hHookShell);
			OutputLastError(buf);
		}
		else
		{
			g_hHookMouseLL = NULL;
		}
	}

	if (g_hHookJournalRecord != NULL)
	{
		if (!UnhookWindowsHookEx(g_hHookJournalRecord))
		{
			wchar_t buf[256] = {0};
			swprintf(buf, L"UnhookWindowsHookEx g_hHookJournalRecord error %p", g_hHookJournalRecord);
			OutputLastError(buf);
		}
		else
		{
			g_hHookJournalRecord = NULL;
		}
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
    return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif

