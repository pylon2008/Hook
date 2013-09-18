#include "stdafx.h"
#include "R3ApiHookFix.h"
#include <string>
#include <vector>


class R3ApiHookFixFunc
{
public:
	R3ApiHookFixFunc(wchar_t* dllName, char* funcName, int fixLength)
	{
		m_dllName = dllName;
		m_funcname = funcName;
		m_SrcCode.resize(fixLength);

		HMODULE hDll=::LoadLibrary(dllName);
		if(hDll==0)
			return;
		char*  pFunction=(char*)::GetProcAddress(hDll,funcName);
		if(pFunction==NULL)
			return;

		memcpy(&m_SrcCode[0], pFunction, m_SrcCode.size());
	}

	void Fix()
	{
		if(m_SrcCode.size()==0)
		{
			return;
		}

		HMODULE hDll=::GetModuleHandle(m_dllName.c_str());
		if(hDll==0)
		{
			return;
		}
		char*  pFunction=(char*)::GetProcAddress(hDll,m_funcname.c_str());
		if(pFunction==NULL)
		{
			return;
		}

		DWORD tmp;
		::VirtualProtect(pFunction, m_SrcCode.size(),PAGE_EXECUTE_READWRITE,&tmp);
		memcpy(pFunction, &m_SrcCode[0], m_SrcCode.size());
		::VirtualProtect(pFunction,m_SrcCode.size(),tmp,&tmp);
	}
protected:
	std::wstring m_dllName;
	std::string m_funcname;
	std::vector<unsigned char> m_SrcCode;
};

///////////////////
std::vector< R3ApiHookFixFunc > g_apifix;

///////////////////////////////////////////////////////////////////////////////////////////////////////

void R3ApiHookFixInit()
{
	g_apifix.push_back( R3ApiHookFixFunc(L"ntdll.dll","DbgBreakPoint",7) );
	g_apifix.push_back( R3ApiHookFixFunc(L"ntdll.dll","DbgUiRemoteBreakin",7) );
	g_apifix.push_back( R3ApiHookFixFunc(L"ntdll.dll","DbgUserBreakPoint",7) );
}

void R3ApiHookFixUninit()
{
	;
}

void RepairR3Api()
{
	for (int idx=0; idx<g_apifix.size(); ++idx)
	{
		g_apifix[idx].Fix();
	}
}
