#include "stdafx.h"
#include "HookUtil.h"
#include <Windows.h>
#include <vector>

namespace
{
	wchar_t g_AppPath[MAX_PATH] = L""; 
	wchar_t g_AppDir[MAX_PATH] = L""; 
}

const wchar_t* GetApplicationPath()
{
	if (g_AppPath[0] == 0)
	{
		GetModuleFileName( NULL, g_AppPath, MAX_PATH );
	}

	return g_AppPath;
}

const wchar_t* GetApplicationDir()
{
	if (g_AppDir[0] == 0)
	{
		if (g_AppPath[0] == 0)
		{
			GetApplicationPath();
		}

		wcscpy(g_AppDir, g_AppPath);

		int tlen = wcslen(g_AppDir);
		for(int i = tlen; i >= 0; --i)
		{
			const wchar_t c = g_AppDir[i];
			if(c == '/' || c == '\\')
			{
				g_AppDir[i+1] = 0;
				break;
			}
		}
	}
	return g_AppDir;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG
#define HOOK_DLL_LOG
#endif

#ifdef HOOK_DLL_LOG
namespace
{
	static FILE*		g_HookLog			= NULL;
};
#endif

void InitUtil()
{
#ifdef HOOK_DLL_LOG
	if (g_HookLog == NULL)
	{
		g_HookLog = fopen("d://hooklog.txt", "w+b");
	}
#endif
}

void UninitUtil()
{
#ifdef HOOK_DLL_LOG
	if (g_HookLog!=NULL)
	{
		fclose(g_HookLog);
	}
#endif
}

void OutputLastError(const wchar_t* errorInfo)
{
#ifdef HOOK_DLL_LOG
	DWORD lastError = GetLastError();
	wchar_t buf[1024] = {0};
	swprintf(buf, L"%s,LastError:%d", errorInfo, lastError);
	MessageBox(0,buf,0,0);
#endif
}

void OutputHookLog(const wchar_t* info)
{
#ifdef HOOK_DLL_LOG
	if (g_HookLog!=NULL)
	{
		std::vector<char> buf;
		buf.resize( wcslen(info)+1024 );
		memset(&buf[0], 0, buf.size());
		WideCharToMultiByte(CP_ACP, NULL,
			info, -1,
			&buf[0],
			buf.size(),NULL,NULL);
		fprintf(g_HookLog, "%d,%d,%s", ::GetCurrentProcessId(), ::GetCurrentThreadId(), &buf[0]);
		fflush(g_HookLog);
	}
#endif
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HMODULE ModuleFromAddress(void* pv) 
{
	MEMORY_BASIC_INFORMATION mbi;
	return ((VirtualQuery(pv,&mbi,sizeof(mbi))!=0)?(HMODULE)mbi.AllocationBase:NULL);
}

void EnumAllModule(unsigned long processId, std::vector<MODULEENTRY32>& output)
{
	HMODULE hThisModule = ModuleFromAddress(EnumAllModule);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,processId);
	if(hSnapshot==INVALID_HANDLE_VALUE) return ;

	MODULEENTRY32 sModItem = {sizeof(sModItem)};
	if(::Module32First(hSnapshot,&sModItem))
	{
		do
		{
			if(sModItem.hModule!=hThisModule)
			{
				output.push_back(sModItem);
			}
		}
		while(::Module32Next(hSnapshot,&sModItem));
	}

	::CloseHandle(hSnapshot);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
