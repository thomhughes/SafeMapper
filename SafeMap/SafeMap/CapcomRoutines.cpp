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

uintptr_t CapcomRoutines::get_kernel_module(const std::string_view kmodule)
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

size_t CapcomRoutines::get_header_size(uintptr_t base)
{
	NON_PAGED_DATA static uintptr_t header_size = { 0 };
	NON_PAGED_DATA static uintptr_t sBase = base;

	CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
	{
		const auto dos_header = (PIMAGE_DOS_HEADER)sBase;
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return;
		const auto nt_headers = (PIMAGE_NT_HEADERS64)sBase;
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return;
		header_size = nt_headers->OptionalHeader.SizeOfHeaders;
	});

	return header_size;
}

uintptr_t CapcomRoutines::get_export(uintptr_t base, uint16_t ordinal)
{
	NON_PAGED_DATA static uintptr_t address = { 0 };
	NON_PAGED_DATA static uintptr_t sBase = { 0 };
	NON_PAGED_DATA static uint16_t sOrdinal = { 0 };

	CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
	{
		const auto dos_header = (PIMAGE_DOS_HEADER)sBase;
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return;
		const auto nt_headers = (PIMAGE_NT_HEADERS64)(sBase + dos_header->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
			return;
		if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return;
		const auto export_ptr = (PIMAGE_EXPORT_DIRECTORY)(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + sBase);
		auto address_of_funcs = (PULONG)(export_ptr->AddressOfFunctions + sBase);
		for (ULONG i = 0; i < export_ptr->NumberOfFunctions; ++i)
		{
			if (export_ptr->Base + (uint16_t)i == sOrdinal) {
				address = address_of_funcs[i] + sBase;
				return;
			}
		}
	});

	return address;
}

uintptr_t CapcomRoutines::get_export(uintptr_t base, const char* name)
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

uintptr_t CapcomRoutines::allocate_pool(size_t size, uint16_t pooltag, POOL_TYPE pool_type, const bool page_align, size_t* out_size)
{
	constexpr auto page_size = 0x1000u;

	NON_PAGED_DATA static uintptr_t address = { 0 };
	NON_PAGED_DATA static uintptr_t sPoolType = pool_type;
	NON_PAGED_DATA static size_t sSize = size;
	NON_PAGED_DATA static uint16_t sPoolTag = pooltag;

	if (page_align && size % page_size != 0)
	{
		auto pages = size / page_size;
		size = page_size * ++pages;
	}
	NON_PAGED_DATA static auto ExAllocatePoolWithTag = KrCtx->GetProcAddress<>("ExAllocatePoolWithTag");

	printf("ExAllocatePoolWithTag: %llx\n", ExAllocatePoolWithTag);
	if (ExAllocatePoolWithTag) {

		CpCtx->ExecuteInKernel(NON_PAGED_LAMBDA()
		{
			uint64_t storeAddy = ExAllocatePoolWithTag(sPoolType, sSize, sPoolTag);
			address = storeAddy;
		});
	}

	if (address && out_size != nullptr)
		*out_size = size;

	return address;
}

uintptr_t CapcomRoutines::allocate_pool(size_t size, POOL_TYPE pool_type, const bool page_align, size_t* out_size) {
	return allocate_pool(size, 0, pool_type, page_align, out_size);
}
