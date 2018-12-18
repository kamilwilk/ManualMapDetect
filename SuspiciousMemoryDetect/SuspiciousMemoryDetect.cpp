// KamilAC.cpp : Defines the entry point for the console application.

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <psapi.h>
#include <aclapi.h>
#include <algorithm>
#include <iterator>
#include <vector>
#include "Tools.h"
#include <shlwapi.h>
#include <ntstatus.h>
#include <tchar.h>
#pragma comment (lib, "Shlwapi.lib")

std::vector<uintptr_t> EnumerateProcessHandles(std::vector<DWORD> processList, const wchar_t * protectedProcess)
{
	std::vector<uintptr_t> handles;

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION pSysHandleInfo;
	ULONG pSysHandleInfoSize = 0x10000;

	do
	{
		pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL, pSysHandleInfoSize, MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(SystemHandleInformation, pSysHandleInfo, pSysHandleInfoSize, &pSysHandleInfoSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			VirtualFree(pSysHandleInfo, 0, MEM_RELEASE);
			pSysHandleInfoSize *= 2;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	for (ULONG i = 0; i < pSysHandleInfo->NumberOfHandles; i++)
	{
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO handle = &pSysHandleInfo->Handles[i];
		HANDLE processHandle;
		HANDLE dupHandle;

		processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, handle->UniqueProcessId);
		if (processHandle == NULL)
			continue; //could not get handle to process

		if (DuplicateHandle(processHandle, (HANDLE)handle->HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
			continue; //could not duplicate handle

		POBJECT_TYPE_INFORMATION pObjTypeInfo;
		ULONG objTypeInfoSize = 0x1000;

		do
		{
			pObjTypeInfo = (POBJECT_TYPE_INFORMATION)VirtualAlloc(NULL, objTypeInfoSize, MEM_COMMIT, PAGE_READWRITE);
			status = NtQueryObject(dupHandle, ObjectTypeInformation, pObjTypeInfo, objTypeInfoSize, &objTypeInfoSize);
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				VirtualFree(pSysHandleInfo, 0, MEM_RELEASE);
				objTypeInfoSize *= 2;
			}
		} while (status == STATUS_INFO_LENGTH_MISMATCH);


		if (NT_SUCCESS(status))
		{

			wchar_t * typeName = (wchar_t *)pObjTypeInfo->TypeName.Buffer;
			if (wcsncmp(typeName, L"Process", pObjTypeInfo->TypeName.Length + 1) == 0)
			{
				wchar_t process[MAX_PATH];
				GetProcessImageFileName(dupHandle, process, MAX_PATH);

				if (wcscmp(process, protectedProcess) == 0)
				{
					LPCWSTR filename = PathFindFileNameW(process);

					wchar_t processWithOpenHandle[MAX_PATH];
					GetProcessImageFileName(processHandle, processWithOpenHandle, MAX_PATH);
					_tprintf(TEXT("\n[+] %s has a handle open to %s"), processWithOpenHandle, filename);
				}
			}
		}

		CloseHandle(dupHandle);
		CloseHandle(processHandle);
		VirtualFree(pObjTypeInfo, 0, MEM_RELEASE);
	}
	VirtualFree(pSysHandleInfo, 0, MEM_RELEASE);

	return handles;
}

std::vector<MODULEENTRY32> GetProcessModules(HANDLE pHandle)
{
	DWORD pid;
	pid = GetProcessId(pHandle);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	std::vector<MODULEENTRY32> me32list;

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnap, &me32))
		{
			do
			{
				me32list.push_back(me32);
			} while (Module32Next(hSnap, &me32));
		}
	}
	CloseHandle(hSnap);
	return me32list;
}

BOOL ScanExecutablePages(HANDLE pHandle)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	uintptr_t procMinAddress = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
	uintptr_t procMaxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

	MEMORY_BASIC_INFORMATION memInfo;

	std::vector<MODULEENTRY32> modInfo;
	modInfo = GetProcessModules(pHandle);

	while (procMinAddress < procMaxAddress)
	{
		if (VirtualQueryEx(pHandle, (LPVOID)procMinAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			//_tprintf(TEXT("\n[-] Region size 0x%08X of 0x%08X"), (uintptr_t)memInfo.RegionSize, (uintptr_t)procMinAddress);
			if (memInfo.Protect == PAGE_EXECUTE_READWRITE ||
				memInfo.Protect == PAGE_EXECUTE_WRITECOPY ||
				memInfo.Protect == PAGE_EXECUTE_READ ||
				memInfo.Protect == PAGE_EXECUTE)
			{
				for (auto& it : modInfo)
				{
					//_tprintf(TEXT("\n[-] Checking region 0x%08X in module at 0x%08X"), (uintptr_t)memInfo.BaseAddress, (uintptr_t)it.modBaseAddr);
					if (IsAddressWithinModuleB((uintptr_t)it.modBaseAddr, it.modBaseSize, (uintptr_t)memInfo.BaseAddress))
					{
						break;
					}

					if (&it == &modInfo.back())
					{
						_tprintf(TEXT("\n[+] Suspicious executable region at 0x%08X - 0x%08X"), (uintptr_t)memInfo.BaseAddress, (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize);
					}
				}
			}
		}
		procMinAddress = procMinAddress + (DWORD)memInfo.RegionSize;
	}
	return FALSE;
}

BOOL ScanProcess(HANDLE hProcess)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	MEMORY_BASIC_INFORMATION memInfo;

	uintptr_t procMinAddress = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
	uintptr_t procMaxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

	while (procMinAddress < procMaxAddress)
	{
		if (VirtualQueryEx(hProcess, (LPVOID)procMinAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			char * buffer;
			if ((memInfo.Protect == PAGE_EXECUTE_READ ||
				memInfo.Protect == PAGE_EXECUTE_WRITECOPY) &&
				memInfo.State == MEM_COMMIT)
			{
				buffer = new char[memInfo.RegionSize];
				SIZE_T bytesRead;

				ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, memInfo.RegionSize, &bytesRead);

				_tprintf(TEXT("\n[-] Looking for Pattern in region starting at 0x%08X"), (uintptr_t)memInfo.BaseAddress);
				if (FindPatternBuffer(buffer, bytesRead, (char*)"\x8D\x84\x83\xBC\x02\x00\x00\x8D\xBB\xE4\x02\x00\x00", (char*)"xxxxxxxxxxxxx"))
				{
					_tprintf(TEXT("\n[+] Pattern found in region starting at 0x%08X"), (uintptr_t)memInfo.BaseAddress);
					CloseHandle(hProcess);
					return TRUE;
				}
				delete[] buffer;
			}
		}
		procMinAddress = procMinAddress + (DWORD)memInfo.RegionSize;
	}
	CloseHandle(hProcess);
	return FALSE;
}

std::vector<DWORD> GetProcessIDs()
{
	std::vector<DWORD> processes;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		if (Process32First(hSnapshot, &pe)) {
			do {
				processes.push_back(pe.th32ProcessID);
			} while (Process32Next(hSnapshot, &pe));
		}
	}
	CloseHandle(hSnapshot);
	return processes;
}

BOOL ScanProcesses(std::vector<DWORD> pIds)
{
	for (std::vector<DWORD>::iterator it = pIds.begin(); it != pIds.end(); ++it)
	{
		HANDLE pHandle;
		if (pHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, *it))
		{
			if (ScanProcess(pHandle))
				return TRUE;
		}
	}
	return FALSE;
}

HANDLE GetHandle(LPCWSTR window)
{
	HWND hwnd = FindWindow(NULL, window);
	HANDLE pHandle;
	DWORD pid;

	if (GetWindowThreadProcessId(hwnd, &pid))
	{
		if (pHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid))
		{
			return pHandle;
		}
	}
	return NULL;
}

BOOL ScanThreads(HANDLE pHandle)
{
	DWORD pid;

	pid = GetProcessId(pHandle);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(THREADENTRY32);

		BOOL Ret = Thread32First(hSnap, &te);
		while (Ret)
		{
			if (te.th32OwnerProcessID == pid)
			{
				HANDLE checkThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (!checkThread)
				{
					continue;
				}

				ULONG_PTR tStartAddress = GetThreadStartAddress(checkThread);

				DWORD oldProtect;
				VirtualProtectEx(checkThread, (LPVOID)tStartAddress, 1000, PAGE_EXECUTE_READ, &oldProtect);

				if (FindPattern((DWORD)tStartAddress, 0x70000, (char*)"\x8B\x45\x10\x50\x8B\x4D\x0C\x51\x8B\x55\x08\x52\xE8", (char*)"xxxxxxxxxxxxx"))
				{
					_tprintf(TEXT("\n[+] Pattern found in thread starting at 0x%08X"), (uintptr_t)tStartAddress);
					VirtualProtectEx(checkThread, (LPVOID)tStartAddress, 1000, oldProtect, NULL);
					CloseHandle(checkThread);
					return TRUE;
				}

				VirtualProtectEx(checkThread, (LPVOID)tStartAddress, 1000, oldProtect, NULL);
				CloseHandle(checkThread);
			}
			Ret = Thread32Next(hSnap, &te);
		}
	}
	return FALSE;
}

int main()
{
	HANDLE processHandle;
	processHandle = GetHandle(L"AssaultCube");
	if (processHandle == NULL)
		return -1;

	wchar_t protectedProcess[MAX_PATH];
	GetProcessImageFileName(processHandle, protectedProcess, MAX_PATH);

	while (true)
	{
		std::vector<DWORD> processList;
		processList = GetProcessIDs();

		EnumerateProcessHandles(processList, protectedProcess);
		ScanExecutablePages(processHandle);
		ScanProcesses(processList);
		ScanThreads(processHandle);

		Sleep((DWORD64)500);
	}
	CloseHandle(processHandle);
	return 0;
}