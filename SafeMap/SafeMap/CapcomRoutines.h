#pragma once

typedef enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,
	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32
} POOL_TYPE;

class CapcomRoutines {
public:
	CapcomRoutines(KernelContext* KrCtx, CapcomContext* CpCtx) : KrCtx(KrCtx), CpCtx(CpCtx) {};
	uintptr_t get_kernel_module(const std::string_view kmodule);
	uintptr_t get_export(uintptr_t base, uint16_t ordinal);
	uintptr_t get_export(uintptr_t base, const char* name);
	size_t get_header_size(uintptr_t base);
	uintptr_t allocate_pool(size_t size, uint16_t pooltag, POOL_TYPE pool_type, const bool page_align, size_t* out_size = nullptr);
	uintptr_t allocate_pool(size_t size, POOL_TYPE pool_type, const bool page_align, size_t* out_size = nullptr);
private:
	KernelContext* KrCtx;
	CapcomContext* CpCtx;
};