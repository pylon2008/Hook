#include "stdafx.h"
#include "HookUtil.h"
#include <Windows.h>
#include <stdio.h>
#include <vector>

static FILE*		g_HookLog			= NULL;

void InitUtil()
{
	if (g_HookLog == NULL)
	{
		g_HookLog = fopen("d://hooklog.txt", "w+b");
	}
}

void UninitUtil()
{
	if (g_HookLog!=NULL)
	{
		fclose(g_HookLog);
	}
}

void OutputLastError(const wchar_t* errorInfo)
{
	DWORD lastError = GetLastError();
	wchar_t buf[1024] = {0};
	swprintf(buf, L"%s,LastError:%d", errorInfo, lastError);
	MessageBox(0,buf,0,0);
}

void OutputHookLog(const wchar_t* info)
{
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
}

