#pragma once
#include <Windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef enum _THREADINFOCLASS
{
	ThreadQuerySetWin32StartAddress = 9,
} THREADINFOCLASS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	DWORD UniqueProcessId;
	WORD HandleType;
	USHORT HandleValue;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemHandleInformation = 0x10
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectHandleFlagInformation,
	ObjectSessionInformation,
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	WORD * Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING ObjectName;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef NTSTATUS(__stdcall * f_NtQueryInformationThread)(HANDLE, THREADINFOCLASS, void*, uintptr_t, uintptr_t*);
auto NtQueryInformationThread = reinterpret_cast<f_NtQueryInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));

typedef NTSTATUS(__stdcall* NtQueryObjectPrototype)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
auto NtQueryObject = reinterpret_cast<NtQueryObjectPrototype>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));

typedef NTSTATUS(__stdcall * f_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
auto NtQuerySystemInformation = reinterpret_cast<f_NtQuerySystemInformation>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));


DWORD FindPattern(DWORD base, DWORD size, char pattern[], char mask[])
{
	for (DWORD retAddress = base; retAddress < (base + size); retAddress++)
	{
		if (*(BYTE*)retAddress == (pattern[0] & 0xff) || mask[0] == '?')
		{
			DWORD startSearch = retAddress;
			for (int i = 0; mask[i] != '\0'; i++, startSearch++)
			{
				if (mask[i] == '?')
					continue;

				if ((pattern[i] & 0xff) != *(BYTE*)startSearch)
					break;

				if ((pattern[i] & 0xff) == *(BYTE*)startSearch && mask[i + 1] == '\0')
				{
					return retAddress;
				}
			}
		}
	}
	return NULL;
}

bool FindPatternBuffer(char * buffer, SIZE_T bytesRead, char * pattern, char mask[])
{
	for (unsigned int i = 0; i < bytesRead; i++)
	{
		if (buffer[i] == (char)(pattern[0] & 0xff) || mask[0] == '?')
		{
			for (int j = i, k = 0; mask[k] != '\0'; j++, k++)
			{
				if (mask[k] == '?')
					continue;

				if ((char)(pattern[k] & 0xff) != buffer[j])
				{
					break;
				}

				if ((char)(pattern[k] & 0xff) == buffer[j] && mask[k + 1] == '\0')
				{
					return true;
				}
			}
		}
	}
	return false;
}

BOOL IsAddressWithinModuleB(uintptr_t modAddress, uintptr_t modSize, uintptr_t address)
{
	if (modAddress <= address && (modAddress + modSize) > address)
		return TRUE;
	return FALSE;
}

uintptr_t GetThreadStartAddress(HANDLE hThread)
{
	uintptr_t ulStartAddress = 0;
	NTSTATUS Ret = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &ulStartAddress, sizeof(uintptr_t), nullptr);

	if (Ret)
		return 0;

	return ulStartAddress;
}