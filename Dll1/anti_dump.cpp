#pragma once
#include <Windows.h>
#include <winternl.h>

void anti_dump()
{
	#if defined(_M_X64)
		const auto peb = (PPEB)__readgsqword(0x60);
	#elif defined(_M_IX86)
		// For 32-bit systems, use __readfsd to get the PEB
		const auto peb = (PPEB)__readfsdword(0x60);
	#else
	#error Unsupported platform
	#endif
	const auto in_load_order_module_list = (PLIST_ENTRY)peb->Ldr->Reserved2[1];
	const auto table_entry = CONTAINING_RECORD(in_load_order_module_list, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
	const auto p_size_of_image = (PULONG)&table_entry->Reserved3[1];
	*p_size_of_image = (ULONG)((INT_PTR)table_entry->DllBase + 0x100000);
};
