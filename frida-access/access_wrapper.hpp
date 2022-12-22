#pragma once

#include <string>
#include <unordered_map>

#include <filesystem>
namespace fs = std::filesystem;


/* https://github.com/Chuyu-Team/MINT */
#include "../third_party/MINT/MINT.h"

/* https://github.com/TsudaKageyu/minhook */
#include "../third_party/minhook/include/MinHook.h"

/* https://github.com/HoShiMin/Kernel-Bridge */
#include <WdkTypes.h>
#include <CtlTypes.h>
#include <User-Bridge.h>



EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)



#define ATTACH_HOOK(name) {																							 \
	MH_STATUS status = MH_STATUS::MH_OK;																			 \
																													 \
	auto& proc = (maps()[#name] = { });																				 \
																													 \
	proc.original = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), #name);									 \
																													 \
	proc.detour = Detour##name;																						 \
																													 \
	status = MH_CreateHook(proc.original, proc.detour, (PVOID*)(&proc.target));										 \
																													 \
	Original##name = decltype(&##name)(proc.target);																 \
}




BOOL IsSelfProcess(HANDLE ProcessHandle) {
	return ProcessHandle == GetCurrentProcess()
		|| GetCurrentProcessId() == GetProcessId(ProcessHandle);
}








decltype(&NtOpenProcess) OriginalNtOpenProcess = NULL;
NTSTATUS
NTAPI
DetourNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtOpenProcess(
			ProcessHandle, 
			DesiredAccess, ObjectAttributes, ClientId);

	return status;
}

decltype(&NtQueryInformationProcess) OriginalNtQueryInformationProcess = NULL;
NTSTATUS
NTAPI
DetourNtQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtQueryInformationProcess(
			ProcessHandle, 
			ProcessInformationClass, 
			ProcessInformation, ProcessInformationLength, ReturnLength);

	return status;
}

decltype(&NtSetInformationProcess) OriginalNtSetInformationProcess = NULL;
NTSTATUS
NTAPI
DetourNtSetInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtSetInformationProcess(
			ProcessHandle,
			ProcessInformationClass,
			ProcessInformation, ProcessInformationLength);

	return status;
}

decltype(&NtSuspendProcess) OriginalNtSuspendProcess = NULL;
NTSTATUS
NTAPI
DetourNtSuspendProcess(
	_In_ HANDLE ProcessHandle
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtSuspendProcess(
			ProcessHandle);

	return status;
}

decltype(&NtResumeProcess) OriginalNtResumeProcess = NULL;
NTSTATUS
NTAPI
DetourNtResumeProcess(
	_In_ HANDLE ProcessHandle
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtResumeProcess(
			ProcessHandle);

	return status;
}

decltype(&NtFreeVirtualMemory) OriginalNtFreeVirtualMemory = NULL;
NTSTATUS
NTAPI
DetourNtFreeVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG FreeType
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtFreeVirtualMemory(
			ProcessHandle, 
			BaseAddress, RegionSize, FreeType);

	return status;
}

decltype(&NtAllocateVirtualMemory) OriginalNtAllocateVirtualMemory = NULL;
NTSTATUS
NTAPI
DetourNtAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtAllocateVirtualMemory(
			ProcessHandle, 
			BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (!IsSelfProcess(ProcessHandle) && STATUS_ACCESS_DENIED == status) {
		return \
			Processes::MemoryManagement::KbAllocUserMemory(
				GetProcessId(ProcessHandle),
				Protect,
				ULONG(*RegionSize), (WdkTypes::PVOID*)(BaseAddress)) ? STATUS_SUCCESS : RtlGetLastNtStatus();
	}

	return status;
}

decltype(&NtReadVirtualMemory) OriginalNtReadVirtualMemory = NULL;
NTSTATUS
NTAPI
DetourNtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_writes_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtReadVirtualMemory(
			ProcessHandle, 
			BaseAddress, Buffer, BufferSize, NumberOfBytesRead);

	return status;
}

decltype(&NtWriteVirtualMemory) OriginalNtWriteVirtualMemory = NULL;
NTSTATUS
NTAPI
DetourNtWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_reads_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtWriteVirtualMemory(
			ProcessHandle, 
			BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);

	if (!IsSelfProcess(ProcessHandle) && STATUS_ACCESS_DENIED == status) {
		BOOL isOk = Processes::MemoryManagement::KbWriteProcessMemory(
			GetProcessId(ProcessHandle),
			(WdkTypes::PVOID)(BaseAddress), Buffer, ULONG(BufferSize));

		if (isOk && NumberOfBytesWritten) *NumberOfBytesWritten = BufferSize;

		return isOk ? STATUS_SUCCESS : RtlGetLastNtStatus();
	}

	return status;
}

decltype(&NtProtectVirtualMemory) OriginalNtProtectVirtualMemory = NULL;
NTSTATUS
NTAPI
DetourNtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtProtectVirtualMemory(
			ProcessHandle, 
			BaseAddress, RegionSize, NewProtect, OldProtect);

	return status;
}

decltype(&NtQueryVirtualMemory) OriginalNtQueryVirtualMemory = NULL;
NTSTATUS
NTAPI
DetourNtQueryVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtQueryVirtualMemory(
			ProcessHandle, 
			BaseAddress, 
			MemoryInformationClass, 
			MemoryInformation, MemoryInformationLength, ReturnLength);

	return status;
}

decltype(&RtlCreateUserThread) OriginalRtlCreateUserThread = NULL;
NTSTATUS
NTAPI
DetourRtlCreateUserThread(
	_In_ HANDLE Process,
	_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	_In_ BOOLEAN CreateSuspended,
	_In_opt_ ULONG ZeroBits,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ SIZE_T CommittedStackSize,
	_In_ PUSER_THREAD_START_ROUTINE StartAddress,
	_In_opt_ PVOID Parameter,
	_Out_opt_ PHANDLE Thread,
	_Out_opt_ PCLIENT_ID ClientId
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalRtlCreateUserThread(
			Process,
			ThreadSecurityDescriptor,
			CreateSuspended,
			ZeroBits, MaximumStackSize, CommittedStackSize,
			StartAddress, Parameter, 
			Thread, ClientId);

	if (!IsSelfProcess(Process)) {
		/* not support Win7: https://github.com/HoShiMin/Kernel-Bridge/issues/42*/
		status =
			Processes::Threads::KbCreateUserThread(
				GetProcessId(Process),
				WdkTypes::PVOID(StartAddress), WdkTypes::PVOID(Parameter),
				CreateSuspended,
				(WdkTypes::CLIENT_ID*)(ClientId), NULL) ? STATUS_SUCCESS : RtlGetLastNtStatus();

		/* thread handle */
		if (ClientId && ClientId->UniqueThread) {
			HANDLE hThread = OpenThread(
				THREAD_ALL_ACCESS, FALSE, DWORD(ClientId->UniqueThread));

			if (hThread && Thread) *Thread = hThread;

			return hThread ? STATUS_SUCCESS : RtlGetLastNtStatus();
		}
	}

	return status;
}

decltype(&NtOpenThread) OriginalNtOpenThread = NULL;
NTSTATUS
NTAPI
DetourNtOpenThread(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtOpenThread(
			ThreadHandle, 
			DesiredAccess, ObjectAttributes, ClientId);

	return status;
}

decltype(&NtSuspendThread) OriginalNtSuspendThread = NULL;
NTSTATUS
NTAPI
DetourNtSuspendThread(
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PULONG PreviousSuspendCount
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtSuspendThread(
			ThreadHandle, PreviousSuspendCount);

	return status;
}

decltype(&NtResumeThread) OriginalNtResumeThread = NULL;
NTSTATUS
NTAPI
DetourNtResumeThread(
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PULONG PreviousSuspendCount
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtResumeThread(
			ThreadHandle, PreviousSuspendCount);

	return status;
}

decltype(&NtQueryInformationThread) OriginalNtQueryInformationThread = NULL;
NTSTATUS
NTAPI
DetourNtQueryInformationThread(
	_In_ HANDLE ThreadHandle,
	_In_ THREADINFOCLASS ThreadInformationClass,
	_Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength,
	_Out_opt_ PULONG ReturnLength
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtQueryInformationThread(
			ThreadHandle,
			ThreadInformationClass,
			ThreadInformation, ThreadInformationLength, ReturnLength);

	return status;
}

decltype(&NtSetInformationThread) OriginalNtSetInformationThread = NULL;
NTSTATUS
NTAPI
DetourNtSetInformationThread(
	_In_ HANDLE ThreadHandle,
	_In_ THREADINFOCLASS ThreadInformationClass,
	_In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtSetInformationThread(
			ThreadHandle,
			ThreadInformationClass,
			ThreadInformation, ThreadInformationLength);

	return status;
}

decltype(&NtGetContextThread) OriginalNtGetContextThread = NULL;
NTSTATUS
NTAPI
DetourNtGetContextThread(
	_In_ HANDLE ThreadHandle,
	_Inout_ PCONTEXT ThreadContext
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtGetContextThread(
			ThreadHandle, ThreadContext);

	return status;
}

decltype(&NtSetContextThread) OriginalNtSetContextThread = NULL;
NTSTATUS
NTAPI
DetourNtSetContextThread(
	_In_ HANDLE ThreadHandle,
	_In_ PCONTEXT ThreadContext
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtSetContextThread(
			ThreadHandle, ThreadContext);

	return status;
}

decltype(&NtClose) OriginalNtClose = NULL;
NTSTATUS
NTAPI
DetourNtClose(
	_In_ _Post_ptr_invalid_ HANDLE Handle
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtClose(
			Handle);

	return status;
}

decltype(&NtWaitForSingleObject) OriginalNtWaitForSingleObject = NULL;
NTSTATUS
NTAPI
DetourNtWaitForSingleObject(
	_In_ HANDLE Handle,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
) {
	NTSTATUS status = STATUS_SUCCESS;

	status = \
		OriginalNtWaitForSingleObject(
			Handle,
			Alertable, Timeout);

	return status;
}








class cls_access_wrapper
{
public:

	inline const auto get_current_path() {
		WCHAR szModuleFile[MAX_PATH] = {};
		GetModuleFileNameW(HINST_THISCOMPONENT, szModuleFile, MAX_PATH);
		return fs::path(szModuleFile).parent_path();
	}


	~cls_access_wrapper() { 
		bool isOk = MH_STATUS::MH_OK == MH_Uninitialize();
	};
	cls_access_wrapper() {
		bool isOk = MH_STATUS::MH_OK == MH_Initialize();
		{
			auto driver = (get_current_path() / L"Kernel-Bridge.sys").wstring();
			isOk = KbLoader::KbLoadAsDriver(driver.c_str());
		}
	};

	struct detour {
		PVOID detour; PVOID original, target;
	};
	std::unordered_map<std::string, detour> maps_ = {  };
	auto& maps() { return maps_; };


	void attach() {

		ATTACH_HOOK(NtOpenProcess);
		ATTACH_HOOK(NtSuspendProcess);
		ATTACH_HOOK(NtResumeProcess);
		ATTACH_HOOK(NtQueryInformationProcess);
		ATTACH_HOOK(NtSetInformationProcess);

		ATTACH_HOOK(NtFreeVirtualMemory);
		ATTACH_HOOK(NtAllocateVirtualMemory);
		ATTACH_HOOK(NtReadVirtualMemory);
		ATTACH_HOOK(NtWriteVirtualMemory);
		ATTACH_HOOK(NtQueryVirtualMemory);
		ATTACH_HOOK(NtProtectVirtualMemory);

		ATTACH_HOOK(RtlCreateUserThread);
		ATTACH_HOOK(NtOpenThread);
		ATTACH_HOOK(NtSuspendThread);
		ATTACH_HOOK(NtResumeThread);
		ATTACH_HOOK(NtGetContextThread);
		ATTACH_HOOK(NtSetContextThread);
		ATTACH_HOOK(NtQueryInformationThread);
		ATTACH_HOOK(NtSetInformationThread);

		ATTACH_HOOK(NtClose);
		ATTACH_HOOK(NtWaitForSingleObject);


		for (auto& proc : maps()) {
			MH_EnableHook(proc.second.original);
		}
	}
	void detach() {
		for (auto& proc : maps()) {
			MH_RemoveHook(proc.second.original);
		} maps().clear();
	}

private:

};