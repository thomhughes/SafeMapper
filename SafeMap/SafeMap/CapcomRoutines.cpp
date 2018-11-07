#include "pch.h"
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <unordered_map>

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

uintptr_t get_kernel_module(const std::string_view kmodule)
{
	NTSTATUS status = 0x0;
	ULONG bytes = 0;
	std::vector<uint8_t> data;
	unsigned long required = 0;


	while ((status = NtQuerySystemInformation(SystemModuleInformation, data.data(), (ULONG)data.size(), &required)) == STATUS_INFO_LENGTH_MISMATCH) {
		data.resize(required);
	}

	if (status == STATUS_SUCCESS)
	{
		return 0;
	}

	const auto modules = reinterpret_cast<PRTL_PROCESS_MODULES>(data.data());
	for (unsigned i = 0; i < modules->NumberOfModules; ++i)
	{
		const auto& driver = modules->Modules[i];
		const auto image_base = reinterpret_cast<uintptr_t>(driver.ImageBase);
		std::string base_name = reinterpret_cast<char*>((uintptr_t)driver.FullPathName + driver.OffsetToFileName);
		const auto offset = base_name.find_last_of(".");

		if (kmodule == base_name)
			return reinterpret_cast<uintptr_t>(driver.ImageBase);

		if (offset != base_name.npos)
			base_name = base_name.erase(offset, base_name.size() - offset);

		if (kmodule == base_name)
			return reinterpret_cast<uintptr_t>(driver.ImageBase);
	}
}

uintptr_t get_system_routine_internal(const std::wstring& name)
{
	NON_PAGED_DATA static uintptr_t address = { 0 };

	NON_PAGED_DATA static UNICODE_STRING unicode_name = { 0 };
	unicode_name.Buffer = (wchar_t*)name.c_str();
	unicode_name.Length = (name.size()) * 2;
	unicode_name.MaximumLength = (name.size() + 1) * 2;

	NON_PAGED_DATA static auto mm_get_system_routine = KrCtx->GetProcAddress<>("MmGetSystemRoutineAddress");

	if (mm_get_system_routine) {
		CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
		{
			uint64_t addy = Khk_CallPassive(mm_get_system_routine, &unicode_name);
			address = addy;
		});
	}

	return address;
}

uintptr_t get_export(uintptr_t base, const char* name)
{
	NON_PAGED_DATA static auto RtlFindExportedRoutineByName = KrCtx->GetProcAddress<>("RtlFindExportedRoutineByName");

	NON_PAGED_DATA static auto sBase = base;
	NON_PAGED_DATA static auto sName = name;

	NON_PAGED_DATA static uintptr_t address = 0;

	if (RtlFindExportedRoutineByName) {
		NON_PAGED_DATA static uintptr_t address = { 0 };

		CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
		{
			uint64_t storeAddy = Khk_CallPassive(RtlFindExportedRoutineByName, sBase, sName);
			address = storeAddy;
		});

	}

	return address;
}