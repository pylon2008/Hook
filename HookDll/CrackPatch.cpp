#include "stdafx.h"
#include "CrackPatch.h"
#include "HookUtil.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////
void MemPatch(void* targetAddr, void* srcCode, void* destCode, unsigned long codeSize)
{
	unsigned long dwReserved = 0;
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
}
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

	// 加密窗口
	unsigned long deltaValue = 0xAF76C;
	char* targetAddr = (char*)exeMod + deltaValue;
	char srcCode[] = {0x89,0x45,0xf8,0x83,0x7d,0xf8,0x00,0x0f,0x85};
	char destCode[] = {0x89,0x65,0xf8,0x83,0x7d,0xf8,0x00,0x0f,0x85};
	unsigned long codeSize = sizeof(srcCode);
	MemPatch(targetAddr, srcCode, destCode, codeSize);

	// 	解密窗口密码输入框
	unsigned long deltaValue2 = 0xD22C0;
	char* targetAddr2 = (char*)exeMod + deltaValue2;
	char srcCode2[] = {0x89,0x45,0xf4,0x83,0x7d,0xf4,0x00,0x0f,0x85};
	char destCode2[] = {0x89,0x65,0xf4,0x83,0x7d,0xf4,0x00,0x0f,0x85};
	unsigned long codeSize2 = sizeof(srcCode2);
	MemPatch(targetAddr2, srcCode2, destCode2, codeSize2);

	// 	解密窗口解密按钮
	unsigned long deltaValue3 = 0xD2436;
	char* targetAddr3 = (char*)exeMod + deltaValue3;
	char srcCode3[] = {0x89,0x45,0xfc,0x83,0x7d,0xfc,0x1e,0x0f,0x8c};
	char destCode3[] = {0x89,0x4d,0xfc,0x83,0x7d,0xfc,0x1e,0x0f,0x8c};
	unsigned long codeSize3 = sizeof(srcCode2);
	MemPatch(targetAddr3, srcCode3, destCode3, codeSize3);







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
