#include "stdafx.h"
#include "CrackPatch.h"
#include "HookUtil.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// 内存替换补丁，直接将内存targetAddr处的代码补丁为destCode，补丁长度为codeSize
// 补丁前检查targetAddr处的代码是否为srcCode
// 用途：将某地址的代码直接替换成其它代码，主要用于比较简单的破解，正好能在指定字节数内暴力破解
void MemPatchReplace(void* targetAddr, void* srcCode, void* destCode, unsigned long codeSize)
{
	unsigned long dwReserved = 0;
	if (!VirtualProtect(targetAddr, codeSize, PAGE_READWRITE,&dwReserved))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"MemPatchReplace--VirtualProtect--PAGE_READWRITE: %p,%d\r\n", targetAddr, codeSize);
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
		swprintf(buf, L"MemPatchReplace--memcmp not equal: %p,%d\r\n", targetAddr, codeSize);
		OutputHookLog(buf);
		return;
	}

	unsigned long dwTemp;
	if (!VirtualProtect(targetAddr, codeSize, dwReserved, &dwTemp))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"MemPatchReplace--VirtualProtect--RESTORE: %p,%d\r\n", targetAddr, codeSize);
		OutputHookLog(buf);
	}
}

// 内存调用补丁，在callFromAddr调用callToAddr处的代码，
// 用途：将某地址的代码调用其它地址处的代码，其它处的代码必须包含本地址原有代码
void MemPatchCall(void* callFromAddr, void* callFromCodeSrc, void* callFromCodeDest, unsigned long callFromSize,
	void* callToAddr, void* callToCodeSrc, void* callToCodeDest, unsigned long callToSize)
{
	MemPatchReplace(callFromAddr, callFromCodeSrc, callFromCodeDest, callFromSize);

	MemPatchReplace(callToAddr, callToCodeSrc, callToCodeDest, callToSize);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// 内存替换补丁，直接将内存targetAddr处的代码补丁为destCode，补丁长度为codeSize
// 补丁前检查targetAddr处的代码是否为srcCode
// 用途：将某地址的代码直接替换成其它代码，主要用于比较简单的破解，正好能在指定字节数内暴力破解
void MemPatchReplaceUnsafe(void* targetAddr, void* destCode, unsigned long codeSize)
{
	unsigned long dwReserved = 0;
	if (!VirtualProtect(targetAddr, codeSize, PAGE_READWRITE,&dwReserved))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"MemPatchReplaceUnsafe--VirtualProtect--PAGE_READWRITE: %p,%d\r\n", targetAddr, codeSize);
		OutputHookLog(buf);
		return;
	}

	memcpy(targetAddr, destCode, codeSize);

	unsigned long dwTemp;
	if (!VirtualProtect(targetAddr, codeSize, dwReserved, &dwTemp))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"MemPatchReplaceUnsafe--VirtualProtect--RESTORE: %p,%d\r\n", targetAddr, codeSize);
		OutputHookLog(buf);
	}
}

// 内存调用补丁(非安全、主要是没有调用处代码检查)，在callFromAddr调用callToAddr处的代码，
// 用途：将某地址的代码调用其它地址处的代码，其它处的代码必须包含本地址原有代码
void MemPatchCallUnsafe(void* callFromAddr, void* callFromCodeDest, unsigned long callFromSize,
	void* callToAddr, void* callToCodeSrc, void* callToCodeDest, unsigned long callToSize)
{
	unsigned long dwReserved = 0;
	if (!VirtualProtect(callToAddr, callToSize, PAGE_READWRITE,&dwReserved))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"MemPatchCallUnsafe--VirtualProtect--PAGE_READWRITE: %p,%d\r\n", callToAddr, callToCodeSrc);
		OutputHookLog(buf);
		return;
	}

	if (memcmp(callToAddr, callToCodeSrc, callToSize)==0)
	{
		unsigned long copySize = callToSize-callFromSize-1;
		memcpy(callToAddr, callToCodeDest, copySize);
		memcpy((char*)callToAddr+copySize, callFromAddr, callFromSize);
		char retn = 0xc3;
		memcpy((char*)callToAddr+copySize+callFromSize, &retn, 1);
	}
	else
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"MemPatchCallUnsafe--memcmp not equal: %p,%d\r\n", callToAddr, callToSize);
		OutputHookLog(buf);
		//return;
	}

	unsigned long dwTemp;
	if (!VirtualProtect(callToAddr, callToSize, dwReserved, &dwTemp))
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"MemPatchCallUnsafe--VirtualProtect--RESTORE: %p,%d\r\n", callToAddr, callToSize);
		OutputHookLog(buf);
	}

	MemPatchReplaceUnsafe(callFromAddr, callFromCodeDest, callFromSize);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////

void DoCrackFloderEncryption()
{
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
	MemPatchReplace(targetAddr, srcCode, destCode, codeSize);

	// 	解密窗口密码输入框
	unsigned long deltaValue2 = 0xD22C0;
	char* targetAddr2 = (char*)exeMod + deltaValue2;
	char srcCode2[] = {0x89,0x45,0xf4,0x83,0x7d,0xf4,0x00,0x0f,0x85};
	char destCode2[] = {0x89,0x65,0xf4,0x83,0x7d,0xf4,0x00,0x0f,0x85};
	unsigned long codeSize2 = sizeof(srcCode2);
	MemPatchReplace(targetAddr2, srcCode2, destCode2, codeSize2);

	// 	解密窗口解密按钮
	unsigned long deltaValue3 = 0xD2436;
	char* targetAddr3 = (char*)exeMod + deltaValue3;
	char srcCode3[] = {0x89,0x45,0xfc,0x83,0x7d,0xfc,0x1e,0x0f,0x8c};
	char destCode3[] = {0x89,0x4d,0xfc,0x83,0x7d,0xfc,0x1e,0x0f,0x8c};
	unsigned long codeSize3 = sizeof(srcCode3);
	MemPatchReplace(targetAddr3, srcCode3, destCode3, codeSize3);

	// 	去掉弹出网页
	unsigned long deltaValue4 = 0xD269C;
	char* targetAddr4 = (char*)exeMod + deltaValue4;
	char srcCode4[] = {0x89,0x45,0xf8,0x83,0x7d,0xf8,0x00,0x0f,0x85};
	char destCode4[] = {0x89,0x65,0xf8,0x83,0x7d,0xf8,0x00,0x0f,0x85};
	unsigned long codeSize4 = sizeof(srcCode4);
	MemPatchReplace(targetAddr4, srcCode4, destCode4, codeSize4);

	// 	未知1
	unsigned long deltaValue5 = 0xD2386;
	char* targetAddr5 = (char*)exeMod + deltaValue5;
	char srcCode5[] = {0x89,0x45,0xf4,0x83,0x7d,0xf4,0x00,0x0f,0x85};
	char destCode5[] = {0x89,0x65,0xf4,0x83,0x7d,0xf4,0x00,0x0f,0x85};
	unsigned long codeSize5 = sizeof(srcCode5);
	MemPatchReplace(targetAddr5, srcCode5, destCode5, codeSize5);

	// 备份补丁代码到系统目录
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

void CrackFloderEncryptionCallBack(void* parm)
{
	::Sleep(5000);
	DoCrackFloderEncryption();
}

void CrackFloderEncryption()
{
	//::CreateThread(0,0,(LPTHREAD_START_ROUTINE)CrackFloderEncryptionCallBack,0,0,0);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
03823F37    E8 C4C0BBFC             CALL 003E0000

037F6B19    E8 EE94BEFC             CALL 003E000C

004ABFAC    E8 8840F3FF             CALL 003E0039


*/
/*
003E0000    C7C0 520D9764           MOV EAX,64970D52
003E0006    A3 A8166F03             MOV DWORD PTR DS:[36F16A8],EAX
003E000B    C3                      RETN
003E000C    C7C0 07EAA86E           MOV EAX,6EA8EA07
003E0012    66:C7C3 28A0            MOV BX,0A028
003E0017    C745 C7 45043834        MOV DWORD PTR SS:[EBP-39],34380445
003E001E    3830                    CMP BYTE PTR DS:[EAX],DH
003E0020    C745 08 31323132        MOV DWORD PTR SS:[EBP+8],32313231
003E0027    C745 0C 31323132        MOV DWORD PTR SS:[EBP+C],32313231
003E002E    0000                    ADD BYTE PTR DS:[EAX],AL
003E0030    0000                    ADD BYTE PTR DS:[EAX],AL
003E0032    0041 66                 ADD BYTE PTR DS:[ECX+66],AL
003E0035    B9 D128C360             MOV ECX,60C328D1
003E003A    83EC 40                 SUB ESP,40
003E003D    C70424 70796C2E         MOV DWORD PTR SS:[ESP],2E6C7970
003E0044    C74424 04 646C6C00      MOV DWORD PTR SS:[ESP+4],6C6C64
003E004C    54                      PUSH ESP
003E004D    E8 E4DB1700             CALL <JMP.&KERNEL32.GetModuleHandleA>
003E0052    C70424 52657061         MOV DWORD PTR SS:[ESP],61706552
003E0059    C74424 04 69725233      MOV DWORD PTR SS:[ESP+4],33527269
003E0061    C74424 08 41706900      MOV DWORD PTR SS:[ESP+8],697041
003E0069    54                      PUSH ESP
003E006A    50                      PUSH EAX
003E006B    E8 D2DB1700             CALL <JMP.&KERNEL32.GetProcAddress>
003E0070    FFD0                    CALL EAX
003E0072    83C4 40                 ADD ESP,40
003E0075    61                      POPAD
003E0076    8BD8                    MOV EBX,EAX
003E0078    8B45 08                 MOV EAX,DWORD PTR SS:[EBP+8]
003E007B    C3                      RETN
003E007C    0000                    ADD BYTE PTR DS:[EAX],AL


*/

void CRCMemCheckRepair(HMODULE exeMod)
{
	HMODULE targetMod = (HMODULE)0xffffffff;

	std::vector<MODULEENTRY32> output;
	EnumAllModule(GetCurrentProcessId(), output);
	for(int idx=0; idx<output.size(); ++idx)
	{
		MODULEENTRY32& sModItem = output[idx];
		if ( wcscmp(L"ai32fplaydk.dll", sModItem.szModule)==0 
			|| wcscmp(L"AI32FPLAYDK.dll", sModItem.szModule)==0 )
		{
			targetMod = sModItem.hModule;
			break;
		}
	}

	if (targetMod == (HMODULE)0xffffffff)
	{
		OutputHookLog( L"Don't find the dll: krnln.fnr" );
	}
	else
	{
		wchar_t buf[1024] = {0};
		swprintf(buf, L"ai32fplaydk.fnr module: %p\r\n", targetMod);
		OutputHookLog(buf);
	}

	// 内存检查第一处
	/*
	unsigned long deltaValue = 0x153F37;
	char* callFromAddr = (char*)targetMod + deltaValue;
	char callFromCodeSrc[] = {0xA3,0xa8,0x16,0xfe,0x04};		// A3 A8166F03             MOV DWORD PTR DS:[36F16A8],EAX
	char callFromCodeDest[] = {0xe8,0xfb,0xff,0xff,0xff};
	unsigned long callFromSize = sizeof(callFromCodeSrc);
	char* callToAddr = (char*)0x004b14c0;
	char callToCodeSrc[] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
	char callToCodeDest[] = {0xc7,0xc0,0x52,0x0d,0x97,0x64,0xA3,0xa8,0x16,0xfe,0x04,0xc3};
	unsigned long callToSize = sizeof(callToCodeSrc);
	MemPatchCall(callFromAddr, callFromCodeSrc, callFromCodeDest,callFromSize,
		callToAddr, callToCodeSrc, callToCodeDest,callToSize);
	*/
	unsigned long deltaValue = 0x153F37;
	char* callFromAddr = (char*)targetMod + deltaValue;
	char callFromCodeDest[] = {0xe8,0x84,0xd5,0x55,0xfb};
	unsigned long callFromSize = sizeof(callFromCodeDest);
	//char* callToAddr = (char*)0x004b14c0; 
	//char* callToAddr = (char*)exeMod + 0xb14c0;
	char* callToAddr = (char*)targetMod + 0x2FBE0;
	int callAddrPara = callToAddr - (callFromAddr+5);
	memcpy(&callFromCodeDest[1], &callAddrPara, 4);
	//char callToCodeSrc[] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
	char callToCodeSrc[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	char callToCodeDest[] = {0xc7,0xc0,0x52,0x0d,0x97,0x64};
	unsigned long callToSize = sizeof(callToCodeSrc);
	MemPatchCallUnsafe(callFromAddr, callFromCodeDest,callFromSize,
		callToAddr, callToCodeSrc, callToCodeDest,callToSize);

	// 内存检查第二处
	unsigned long deltaValue2 = 0x126B19;
	char* callFromAddr2 = (char*)targetMod + deltaValue2;
	char callFromCodeSrc2[] = {0x41,0x66,0xb9,0xd1,0x28};		// A3 A8166F03             MOV DWORD PTR DS:[36F16A8],EAX
	char callFromCodeDest2[] = {0xe8,0xd2,0xa9,0xdc,0xfc};
	unsigned long callFromSize2 = sizeof(callFromCodeSrc2);
	//char* callToAddr2 = (char*)0x004b14f0;
	//char* callToAddr2 = (char*)exeMod + 0xb14f0;
	char* callToAddr2 = (char*)targetMod + 0x2FC10;
	int callAddrPara2 = callToAddr2 - (callFromAddr2+5);
	memcpy(&callFromCodeDest2[1], &callAddrPara2, 4);
	char callToCodeSrc2[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	char callToCodeDest2[] = {0xc7,0xc0,0x07,0xea,0xa8,0x6e,0x41,0x66,0xb9,0xd1,0x28,0xc3};
	unsigned long callToSize2 = sizeof(callToCodeSrc2);
	MemPatchCall(callFromAddr2, callFromCodeSrc2, callFromCodeDest2,callFromSize2,
		callToAddr2, callToCodeSrc2, callToCodeDest2,callToSize2);

	/*
	unsigned long deltaValue2 = 0x126B19;
	char* callFromAddr2 = (char*)targetMod + deltaValue2;
	char callFromCodeDest2[] = {0xe8,0xd2,0xa9,0xdc,0xfc};
	unsigned long callFromSize2 = sizeof(callFromCodeDest2);
	char* callToAddr2 = (char*)0x004b14f0;
	char callToCodeSrc2[] = {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90};
	char callToCodeDest2[] = {0xc7,0xc0,0x07,0xea,0xa8,0x6e};
	unsigned long callToSize2 = sizeof(callToCodeSrc2);
	MemPatchCallUnsafe(callFromAddr2, callFromCodeDest2,callFromSize2,
		callToAddr2, callToCodeSrc2, callToCodeDest2,callToSize2);
	*/

	// 断点检查第一处
	//0042A498
	unsigned long deltaValue4 = 0x2A499;
	char* targetAddr4 = (char*)exeMod + deltaValue4;
	char srcCode4[] = {0xC0};
	char destCode4[] = {0xC9};
	unsigned long codeSize4 = sizeof(srcCode4);
	MemPatchReplace(targetAddr4, srcCode4, destCode4, codeSize4);
}

void DoCrackTianLangXingEncryption()
{
	HMODULE exeMod = ::GetModuleHandle(0);
	wchar_t buf[1024] = {0};
	swprintf(buf, L"GetModuleHandle(0): %p\r\n", exeMod);
	OutputHookLog(buf);

	CRCMemCheckRepair(exeMod);
}

void CrackTianLangXingEncryption()
{
	DoCrackTianLangXingEncryption();
}