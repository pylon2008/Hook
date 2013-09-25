#include "stdafx.h"
#include "CrackPatch.h"
#include "HookUtil.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////
void CrackFloderEncryptionCallBack(void* parm)
{
	::Sleep(5000);
	HMODULE targetMod = (HMODULE)0xffffffff;

	std::vector<MODULEENTRY32> output;
	EnumAllModule(GetCurrentProcessId(), output);
	for(int idx=0; idx<output.size(); ++idx)
	{
		MODULEENTRY32& sModItem = output[idx];
		if ( wcscmp(L"krnln.fnr", sModItem.szModule)==0 
			|| wcscmp(L"KRNLN.fnr", sModItem.szModule)==0 )
		{
			targetMod = sModItem.hModule;
			break;
		}
	}

	if (targetMod == (HMODULE)0xffffffff)
	{
		OutputHookLog( L"Don't find the dll: krnln.fnr" );
	}

	HMODULE exeMod = ::GetModuleHandle(0);
	wchar_t buf[1024] = {0};
	swprintf(buf, L"GetModuleHandle(0): %p\r\n", exeMod);
	OutputHookLog(buf);

	unsigned long deltaValue = 0xAF76C;
	char* targetAddr = (char*)exeMod + deltaValue;

	char srcCode[] = {
		0x89,
		0x45,
		0xf8,
		0x83,
		0x7d,
		0xf8,
		0x00,
		0x0f,
		0x85
	};
	char destCode[] = {
		0x89,
		0x65,
		0xf8,
		0x83,
		0x7d,
		0xf8,
		0x00,
		0x0f,
		0x85
	};

	unsigned long dwReserved = 0;
	unsigned long codeSize = sizeof(srcCode);
	if (!VirtualProtect(targetAddr, codeSize, PAGE_READWRITE,&dwReserved))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"VirtualProtect--PAGE_READWRITE: %p,%d\r\n", targetAddr, codeSize);
		OutputHookLog(buf);
		return;
	}

	if (memcmp(targetAddr, srcCode, codeSize)==0)
	{
		memcpy(targetAddr, destCode, codeSize);
	}
	else
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"memcmp not equal: %p,%d\r\n", targetAddr, codeSize);
		OutputHookLog(buf);
		return;
	}

	unsigned long dwTemp;
	if (!VirtualProtect(targetAddr, codeSize, dwReserved, &dwTemp))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"VirtualProtect--RESTORE: %p,%d\r\n", targetAddr, codeSize);
		OutputHookLog(buf);
	}

	wchar_t srcDll[256] = {0};
	wcscpy(srcDll, GetApplicationDir());
	wcscat(srcDll, L"pyl.dll");
	wchar_t* destDll = L"C:\\WINDOWS\\pyl.dll";
	bool isCopy = CopyFileW(srcDll, destDll, false);
	if (1)
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"CopyFileW: %s,%s,%d\r\n", srcDll, destDll, isCopy);
		OutputHookLog(buf);
	}
}

void CrackFloderEncryption()
{
	::CreateThread(0,0,(LPTHREAD_START_ROUTINE)CrackFloderEncryptionCallBack,0,0,0);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
