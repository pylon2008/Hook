#include "stdafx.h"
#include "R3ApiHookFix.h"
#include <string>
#include <vector>
#include <stdio.h>


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

void R3ApiHookFixInitInline()
{
	g_apifix.push_back( R3ApiHookFixFunc(L"ntdll.dll","DbgBreakPoint",7) );
	g_apifix.push_back( R3ApiHookFixFunc(L"ntdll.dll","DbgUiRemoteBreakin",7) );
	g_apifix.push_back( R3ApiHookFixFunc(L"ntdll.dll","DbgUserBreakPoint",7) );
}

void RepairR3ApiInline()
{
	for (int idx=0; idx<g_apifix.size(); ++idx)
	{
		g_apifix[idx].Fix();
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////
struct ImportFunc 
{
	std::string m_FuncName;
	unsigned long m_NameRVA;
	unsigned long m_AddrRaw;
	unsigned long m_AddrImport;
	unsigned long m_AddrRVA;
};

struct DllImportTable 
{
	std::string m_DllName;
	std::vector< ImportFunc > m_ImportFuncs;
	unsigned long m_OriginalFirstThunk;
	unsigned long m_FirstThunk;
	unsigned long m_DescriptorAddr;
	unsigned long m_ForwarderChain;
	unsigned long m_TimeDateStamp;
};

struct ModuleDllImportTable 
{
	MODULEENTRY32 m_Module;
	std::vector< DllImportTable > m_IAT;
};

typedef std::vector< ModuleDllImportTable > ExeModuleImportTables;
ExeModuleImportTables g_apifixIATBefore;
ExeModuleImportTables g_apifixIATAfter;

//////////////////////////////////////////////////////////////////////////////////////////////////////
struct ForwarderRef
{
	std::string m_Name;
	unsigned long m_Addr;
	IMAGE_BOUND_FORWARDER_REF m_Ref;
};

struct DllBoundImportTable 
{
	std::string m_DllName;
	unsigned long m_Addr;
	IMAGE_BOUND_IMPORT_DESCRIPTOR m_Descriptor;
	std::vector< ForwarderRef > m_Refs;
};

struct ModuleDllBoundImportTable 
{
	MODULEENTRY32 m_Module;
	char* m_Base;
	std::vector< DllBoundImportTable > m_BIAT;
};

typedef std::vector< ModuleDllBoundImportTable > ExeModuleBoundImportTables;
ExeModuleBoundImportTables g_apifixBIAT;
//////////////////////////////////////////////////////////////////////////////////////////////////////


void OutputIATFullInfo(const ExeModuleImportTables& output)
{
	std::vector<unsigned char> str;
	str.resize(1024*1024);
	char* buf = (char*)&str[0];
	memset(buf, 0, str.size());
	sprintf(buf+strlen(buf), "\r\n%s,%d\r\n", "====>应用程序外部依赖Dll数量import table：", output.size());

	for (int idx=0; idx<output.size(); ++idx)
	{
		const ModuleDllImportTable& moduleTable = output[idx];
		char module[1024] = {0};
		char exePath[1024] = {0};
		WideCharToMultiByte(CP_ACP, NULL,moduleTable.m_Module.szModule, -1,module,sizeof(module),NULL,NULL);
		WideCharToMultiByte(CP_ACP, NULL,moduleTable.m_Module.szExePath, -1,exePath,sizeof(exePath),NULL,NULL);
		sprintf(buf+strlen(buf), "========>%p,%s,%s\r\n", moduleTable.m_Module.hModule, 
			module,
			exePath);
		for (int modIdx=0; modIdx<moduleTable.m_IAT.size(); ++modIdx)
		{
			const DllImportTable& table = moduleTable.m_IAT[modIdx];
			sprintf(buf+strlen(buf), "============>%s,%d,%p,%p,%p,%p,%p,%s\r\n", 
				&table.m_DllName[0], table.m_ImportFuncs.size(), 
				table.m_DescriptorAddr, table.m_ForwarderChain, table.m_TimeDateStamp, table.m_OriginalFirstThunk, table.m_FirstThunk, module);
			for (int funIdx=0; funIdx<table.m_ImportFuncs.size(); ++funIdx)
			{
				const ImportFunc& func = table.m_ImportFuncs[funIdx];
				const char* funName = 0;
				if (func.m_FuncName.size() > 0)
				{
					funName = &func.m_FuncName[0];
				}
				sprintf(buf+strlen(buf), "================>%s(%p),%p,%p(%p)\r\n", funName, func.m_NameRVA, func.m_AddrRaw, func.m_AddrImport, func.m_AddrRVA);
			}
			sprintf(buf+strlen(buf), "%s", "\r\n");
		}
	}

	std::vector<wchar_t> wstr;
	wstr.resize( str.size() );
	memset( &wstr[0], 0, wstr.size()*sizeof(wchar_t) );
	MultiByteToWideChar(CP_ACP, NULL,
		buf, -1,
		&wstr[0],
		wstr.size()*sizeof(wchar_t));
	OutputHookLog( &wstr[0] );
}

void OutputBIATFullInfo(const ExeModuleBoundImportTables& output)
{
	std::vector<unsigned char> str;
	str.resize(1024*1024);
	char* buf = (char*)&str[0];
	memset(buf, 0, str.size());
	sprintf(buf+strlen(buf), "\r\n%s,%d\r\n", "====>应用程序外部依赖Dll数量bound import table：", output.size());

	for (int tableIdx=0; tableIdx<output.size(); ++tableIdx)
	{
		const ModuleDllBoundImportTable& table = output[tableIdx];
		char module[1024] = {0};
		char exePath[1024] = {0};
		WideCharToMultiByte(CP_ACP, NULL,table.m_Module.szModule, -1,module,sizeof(module),NULL,NULL);
		WideCharToMultiByte(CP_ACP, NULL,table.m_Module.szExePath, -1,exePath,sizeof(exePath),NULL,NULL);
		sprintf(buf+strlen(buf), "========>%p,%s,%s\r\n", table.m_Module.hModule, 
			module,
			exePath);

		for (int modIdx=0; modIdx<table.m_BIAT.size(); ++modIdx)
		{
			const DllBoundImportTable& import = table.m_BIAT[modIdx];
			sprintf(buf+strlen(buf), "============>%s,%p,%d\r\n", &import.m_DllName[0], import.m_Addr, import.m_Descriptor.NumberOfModuleForwarderRefs);
			for (int refIdx=0; refIdx<import.m_Refs.size(); ++refIdx)
			{
				const ForwarderRef& ref = import.m_Refs[refIdx];
				sprintf(buf+strlen(buf), "================>%s,%p,%d\r\n", &ref.m_Name[0], ref.m_Addr, ref.m_Ref.TimeDateStamp);
			}
			sprintf(buf+strlen(buf), "%s", "\r\n");
		}
	}

	std::vector<wchar_t> wstr;
	wstr.resize( str.size() );
	memset( &wstr[0], 0, wstr.size()*sizeof(wchar_t) );
	MultiByteToWideChar(CP_ACP, NULL,
		buf, -1,
		&wstr[0],
		wstr.size()*sizeof(wchar_t));
	OutputHookLog( &wstr[0] );
}

unsigned long GetFuncAddr(char* dllName, char* funcName)
{
	HMODULE hMod = ::LoadLibraryA(dllName);
	unsigned long addr = (unsigned long)::GetProcAddress(hMod, funcName);
	::FreeLibrary(hMod);
	return addr;
}

bool FilterModule(const char* moduleName)
{
	//return true;
	static char* filterModules[] = {
		"kernel32.dll",
		"KERNEL32.dll",
		"ntdll.dll",
		"NTDLL.dll",
		"USER32.dll",
		"user32.dll",
		"COMCTL32.dll",
		"comctl32.dll",
		"SHLWAPI.dll",
		"shlwapi.dll",
		"msvcrt.dll",
		"MSCRVT.dll",
		"MSVCRT.dll",
		"msvcrt.dll",
		"PSAPI.dll",
		"psapi.dll",
		"ADPAVI32.dll",
		"adpavi.dll",
		"SHELL32.dll",
		"shell32.dll",
	};
	bool isFilter = false;
	for (int idx=0; idx<sizeof(filterModules)/sizeof(char*); ++idx)
	{
		if(strcmp(moduleName, filterModules[idx])==0)
		{
			isFilter = true;
			break;
		}
	}
	return isFilter;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////


void R3ApiBIATScanModule(MODULEENTRY32& mod, ExeModuleBoundImportTables& output)
{
	ModuleDllBoundImportTable moduleTable;
	memcpy(&moduleTable.m_Module, &mod, sizeof(mod));

	PIMAGE_DOS_HEADER  pDosHeader;
	PIMAGE_NT_HEADERS  pNTHeaders;
	PIMAGE_OPTIONAL_HEADER   pOptHeader;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR  pImportDescriptor;
	HMODULE hMod = mod.hModule;
	pDosHeader = (PIMAGE_DOS_HEADER)hMod;
	pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hMod + pDosHeader->e_lfanew);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER)&(pNTHeaders->OptionalHeader);
	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size == 0)
	{
		return;
	}
	pImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((BYTE *)hMod + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
	moduleTable.m_Base = (char*)pImportDescriptor;

	IMAGE_BOUND_IMPORT_DESCRIPTOR nullDescriptor;
	memset(&nullDescriptor, 0, sizeof(nullDescriptor));
	while(true)
	{
		if (memcmp(pImportDescriptor, &nullDescriptor, sizeof(nullDescriptor)) == 0)
		{
			break;
		}

		DllBoundImportTable dllBoundImportTable;
		dllBoundImportTable.m_Addr = (unsigned long)pImportDescriptor;
		dllBoundImportTable.m_Descriptor = *pImportDescriptor;
		dllBoundImportTable.m_DllName = moduleTable.m_Base + dllBoundImportTable.m_Descriptor.OffsetModuleName;

		PIMAGE_BOUND_FORWARDER_REF pForwarderRef = (PIMAGE_BOUND_FORWARDER_REF)(pImportDescriptor+1);
		for (int idx=0; idx<pImportDescriptor->NumberOfModuleForwarderRefs; ++idx)
		{
			ForwarderRef ref;
			ref.m_Addr = (unsigned long)pForwarderRef;
			ref.m_Ref = *pForwarderRef;
			ref.m_Name = ref.m_Ref.OffsetModuleName + moduleTable.m_Base;
			dllBoundImportTable.m_Refs.push_back(ref);
			pForwarderRef++;
		}

		moduleTable.m_BIAT.push_back(dllBoundImportTable);

		pImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((char*)(pImportDescriptor + 1) + (pImportDescriptor->NumberOfModuleForwarderRefs+0) * sizeof(IMAGE_BOUND_FORWARDER_REF));
	}

	output.push_back(moduleTable);
}

void R3ApiIATScanModule(MODULEENTRY32& mod, ExeModuleImportTables& output)
{
	ModuleDllImportTable moduleTable;
	memcpy(&moduleTable.m_Module, &mod, sizeof(mod));

	PIMAGE_DOS_HEADER  pDosHeader;
	PIMAGE_NT_HEADERS  pNTHeaders;
	PIMAGE_OPTIONAL_HEADER   pOptHeader;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDescriptor;
	PIMAGE_THUNK_DATA         pThunkData, pThunkDataOrig;
	PIMAGE_IMPORT_BY_NAME     pImportByName;

	HMODULE hMod = moduleTable.m_Module.hModule;
	pDosHeader = (PIMAGE_DOS_HEADER)hMod;
	pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hMod + pDosHeader->e_lfanew);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER)&(pNTHeaders->OptionalHeader);
	if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
	{
		return;
	}
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hMod + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	IMAGE_IMPORT_DESCRIPTOR nullDescriptor;
	memset(&nullDescriptor, 0, sizeof(nullDescriptor));
	IMAGE_THUNK_DATA nullThunk;
	memset(&nullThunk, 0, sizeof(nullThunk));
	while(memcmp(pImportDescriptor, &nullDescriptor, sizeof(nullDescriptor)) != 0)
	{
		char* dllname = (char *)((BYTE *)hMod + pImportDescriptor->Name);
		if ( FilterModule(dllname) == true )
		{
			DllImportTable dllImportTable;
			dllImportTable.m_DllName = dllname;
			dllImportTable.m_TimeDateStamp = pImportDescriptor->TimeDateStamp;
			dllImportTable.m_ForwarderChain = pImportDescriptor->ForwarderChain;
			dllImportTable.m_DescriptorAddr = (unsigned long)pImportDescriptor;
			dllImportTable.m_OriginalFirstThunk = pImportDescriptor->OriginalFirstThunk;
			dllImportTable.m_FirstThunk = pImportDescriptor->FirstThunk;
			pThunkDataOrig = (PIMAGE_THUNK_DATA)((BYTE *)hMod + pImportDescriptor->OriginalFirstThunk);
			pThunkData = (PIMAGE_THUNK_DATA)((BYTE *)hMod + pImportDescriptor->FirstThunk);
			int no = 1;
			while( memcmp(pThunkData, &nullThunk, sizeof(nullThunk)) != 0 )
			{
				/*if (memcmp(pThunkDataOrig, &nullThunk, sizeof(nullThunk)) != 0)
				{
					wchar_t buf[1024] = {0};
					swprintf(buf, L"OriginalFirstThunk and FirstThunk not equal: %p, %p\r\n", &pThunkData->u1.Function, &pThunkDataOrig->u1.Function);
					OutputHookLog(buf);
				}
				else
				{
					wchar_t buf[1024] = {0};
					swprintf(buf, L"OriginalFirstThunk and FirstThunk equal: %p, %p\r\n", &pThunkData->u1.Function, &pThunkDataOrig->u1.Function);
					OutputHookLog(buf);
				}*/
				char* funname = 0;
				if ((pThunkDataOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) != IMAGE_ORDINAL_FLAG)
				{
					pImportByName = (PIMAGE_IMPORT_BY_NAME)(pThunkDataOrig->u1.AddressOfData + (ULONG)hMod);
					funname = (char*)&pImportByName->Name[0];
				}
				else
				{
					funname = 0;
				}

				//PDWORD lpAddr = (DWORD *)((BYTE *)hMod + (DWORD)pImportDescriptor->FirstThunk) +(no-1);
				PDWORD lpAddr = (DWORD *)(pThunkData);
				if (funname != 0)
				{
					ImportFunc funcInfo;
					funcInfo.m_FuncName = funname;
					funcInfo.m_NameRVA = (unsigned long)funname;
					funcInfo.m_AddrImport = (unsigned long)(*(unsigned long*)lpAddr);
					funcInfo.m_AddrRVA = (unsigned long)lpAddr;
					funcInfo.m_AddrRaw = GetFuncAddr(dllname, funname);
					dllImportTable.m_ImportFuncs.push_back(funcInfo);
				}
				no++;
				pThunkData++;
				pThunkDataOrig++;
			}
			moduleTable.m_IAT.push_back(dllImportTable);
		}
		pImportDescriptor++;
	}
	output.push_back(moduleTable);
}

void ScanAllR3ApiModules()
{
	std::vector<MODULEENTRY32> output;
	EnumAllModule(GetCurrentProcessId(), output);
	for(int idx=0; idx<output.size(); ++idx)
	{
		MODULEENTRY32 sModItem = output[idx];
		R3ApiIATScanModule(sModItem, g_apifixIATBefore);
		R3ApiBIATScanModule(sModItem, g_apifixBIAT);
	}

	OutputIATFullInfo(g_apifixIATBefore);
	OutputBIATFullInfo(g_apifixBIAT);
}

//HMODULE ModuleFromAddress(void* pv) 
//{
//	MEMORY_BASIC_INFORMATION mbi;
//	return ((VirtualQuery(pv,&mbi,sizeof(mbi))!=0)?(HMODULE)mbi.AllocationBase:NULL);
//}
//
//void ScanAllR3ApiModules()
//{
//	HMODULE hThisModule = ModuleFromAddress(ScanAllR3ApiModules);
//
//	// 遍历进程中所有模块
//	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetCurrentProcessId());
//	if(hSnapshot==INVALID_HANDLE_VALUE) return ;
//
//	MODULEENTRY32 sModItem = {sizeof(sModItem)};
//	if(::Module32First(hSnapshot,&sModItem))
//	{
//		do
//		{
//			// 下面的判断，是排除对当前模块的API hook,一般情况下，我们会把该API hook的代码放在一个独立的dll中。
//			if(sModItem.hModule!=hThisModule)
//			{
//				// 替换模块的IAT
//				R3ApiIATScanModule(sModItem, g_apifixIATBefore);
//				R3ApiBIATScanModule(sModItem, g_apifixBIAT);
//			}
//		}
//		while(::Module32Next(hSnapshot,&sModItem));
//	}
//
//	::CloseHandle(hSnapshot);
//
//	OutputIATFullInfo(g_apifixIATBefore);
//	OutputBIATFullInfo(g_apifixBIAT);
//}

void R3ApiHookFixInitIAT()
{
}

void RepairR3ApiIAT()
{
	ScanAllR3ApiModules();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

void R3ApiHookFixInit()
{
	//R3ApiHookFixInitInline();
	//R3ApiHookFixInitIAT();
}

void R3ApiHookFixUninit()
{
	;
}

void RepairR3Api()
{
	//RepairR3ApiInline();
	//RepairR3ApiIAT();
}
