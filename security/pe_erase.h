#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/memory.h"

#if KC_ENABLE_PE_ERASE

#if !defined(_NTDDK_) && !defined(_WDMDDK_)

struct _MDL;

extern "C" {
    unsigned char __stdcall MmIsAddressValid(void* VirtualAddress);

    _MDL* __stdcall IoAllocateMdl(void* VirtualAddress, unsigned long Length,
        unsigned char SecondaryBuffer, unsigned char ChargeQuota, void* Irp);
    void __stdcall IoFreeMdl(_MDL* Mdl);
    void __stdcall MmProbeAndLockPages(_MDL* MemoryDescriptorList,
        char AccessMode, int Operation);
    void* __stdcall MmMapLockedPagesSpecifyCache(_MDL* MemoryDescriptorList,
        char AccessMode, int CacheType, void* RequestedAddress,
        unsigned long BugCheckOnFailure, unsigned long Priority);
    void __stdcall MmUnmapLockedPages(void* BaseAddress, _MDL* MemoryDescriptorList);
    void __stdcall MmUnlockPages(_MDL* MemoryDescriptorList);

    long __stdcall PsCreateSystemThread(void** ThreadHandle, unsigned long DesiredAccess,
        void* ObjectAttributes, void* ProcessHandle, void* ClientId,
        void (*StartRoutine)(void*), void* StartContext);
    long __stdcall PsTerminateSystemThread(long ExitStatus);
    long __stdcall KeDelayExecutionThread(char WaitMode, unsigned char Alertable, __int64* Interval);
    long __stdcall ZwClose(void* Handle);
}

#endif

// RtlSecureZeroMemory is a forceinline in WDK, not an export.
// we implement our own volatile version to ensure the compiler doesn't optimize it away.
namespace kernelcloak {
namespace security {
namespace detail {

KC_FORCEINLINE void secure_zero(void* dst, size_t len) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(dst);
    while (len--) *p++ = 0;
}

} // namespace detail
} // namespace security
} // namespace kernelcloak

namespace kernelcloak {
namespace security {

namespace detail {

struct pe_dos_header {
    uint16_t e_magic;
    uint8_t  _pad[58];
    int32_t  e_lfanew;
};

struct pe_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct pe_data_directory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct pe_optional_header64 {
    uint16_t Magic;
    uint8_t  _pad1[14];
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint8_t  _pad2[16];
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory DataDirectory[16];
};

struct pe_nt_headers64 {
    uint32_t Signature;
    pe_file_header FileHeader;
    pe_optional_header64 OptionalHeader;
};

#pragma pack(push, 1)
struct pe_section_header {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

// find own driver base by scanning backward from known function address
KC_NOINLINE inline void* find_driver_base() {
    __try {
        auto ptr = reinterpret_cast<uintptr_t>(&find_driver_base);
        ptr &= ~static_cast<uintptr_t>(0xFFF);

        for (int i = 0; i < 0x4000; ++i) {
            if (!MmIsAddressValid(reinterpret_cast<void*>(ptr)))
                goto skip;

            {
                auto* dos = reinterpret_cast<pe_dos_header*>(ptr);
                if (dos->e_magic == 0x5A4D && dos->e_lfanew > 0 && dos->e_lfanew < 0x1000) {
                    auto* nt = reinterpret_cast<pe_nt_headers64*>(ptr + dos->e_lfanew);
                    if (MmIsAddressValid(nt) && nt->Signature == 0x00004550)
                        return reinterpret_cast<void*>(ptr);
                }
            }

        skip:
            ptr -= 0x1000;
        }
    } __except (1) {}

    return nullptr;
}

//
// Zero memory through an MDL writable remap.
// Header pages are mapped R/O by the loader so direct writes fault with 0xBE.
// We lock the physical pages and create a second VA mapping with write access.
//
KC_NOINLINE inline bool mdl_zero_memory(void* addr, size_t len) {
    auto* mdl = IoAllocateMdl(addr, static_cast<unsigned long>(len), 0, 0, nullptr);
    if (!mdl)
        return false;

    __try {
        MmProbeAndLockPages(mdl, 0 /*KernelMode*/, 0 /*IoReadAccess*/);
    } __except (1) {
        IoFreeMdl(mdl);
        return false;
    }

    auto* mapped = MmMapLockedPagesSpecifyCache(
        mdl, 0 /*KernelMode*/, 1 /*MmCached*/, nullptr, 0, 16 /*NormalPagePriority*/);

    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return false;
    }

    secure_zero(mapped, len);

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return true;
}

struct pe_erase_context {
    void* base;
    unsigned long size;
};

KC_NOINLINE inline void pe_erase_thread(void* param) {
    auto* ctx = static_cast<pe_erase_context*>(param);

    /*++

    MiSnapDriverRange parses our PE section table during IopLoadDriver
    cleanup after DriverEntry returns. If headers are already zeroed,
    it walks into NULL and we get bugcheck 0x7E. 150ms is plenty
    for the loader to finish.

    --*/
    __int64 interval = -1500000;
    KeDelayExecutionThread(0, 0, &interval);

    mdl_zero_memory(ctx->base, ctx->size);

    core::kc_pool_free(ctx);
    PsTerminateSystemThread(0);
}

//
// Erase PE headers from driver image. Defers the actual zeroing
// to a system thread so we don't race MiFreeDriverInitialization.
//
KC_NOINLINE inline bool erase_pe_headers() {
    __try {
        void* base = find_driver_base();
        if (!base)
            return false;

        auto* raw = reinterpret_cast<uint8_t*>(base);
        auto* dos = reinterpret_cast<pe_dos_header*>(base);

        if (dos->e_magic != 0x5A4D)
            return false;

        int32_t lfanew = dos->e_lfanew;
        if (lfanew <= 0 || lfanew >= 0x1000)
            return false;

        auto* nt = reinterpret_cast<pe_nt_headers64*>(raw + lfanew);
        if (!MmIsAddressValid(nt) || nt->Signature != 0x00004550)
            return false;

        uint16_t num_sections = nt->FileHeader.NumberOfSections;
        uint16_t opt_hdr_size = nt->FileHeader.SizeOfOptionalHeader;

        if (num_sections == 0 || num_sections > 96)
            return false;
        if (opt_hdr_size < sizeof(pe_optional_header64) || opt_hdr_size > 0x1000)
            return false;

        auto* first_section = reinterpret_cast<pe_section_header*>(
            reinterpret_cast<uint8_t*>(&nt->OptionalHeader) + opt_hdr_size);
        auto* last_section = &first_section[num_sections];

        uintptr_t erase_end = reinterpret_cast<uintptr_t>(last_section);
        uintptr_t erase_start = reinterpret_cast<uintptr_t>(base);
        size_t erase_size = erase_end - erase_start;

        uint32_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
        if (erase_size > size_of_headers)
            erase_size = size_of_headers;
        if (erase_size > 0x2000)
            erase_size = 0x2000;

        for (size_t offset = 0; offset < erase_size; offset += 0x1000) {
            if (!MmIsAddressValid(raw + offset))
                return false;
        }
        if (erase_size > 0 && !MmIsAddressValid(raw + erase_size - 1))
            return false;

        auto* ctx = static_cast<pe_erase_context*>(
            core::kc_pool_alloc(sizeof(pe_erase_context)));
        if (!ctx)
            return false;

        ctx->base = base;
        ctx->size = static_cast<unsigned long>(erase_size);

        void* thread_handle = nullptr;
        long status = PsCreateSystemThread(
            &thread_handle, 0, nullptr, nullptr, nullptr,
            pe_erase_thread, ctx);

        if (status < 0) {
            core::kc_pool_free(ctx);
            return false;
        }

        ZwClose(thread_handle);
        return true;
    } __except (1) {
        return false;
    }
}

} // namespace detail

} // namespace security
} // namespace kernelcloak

// erase PE headers from own driver image. safe to call from DriverEntry -
// erasure is deferred until the kernel loader finishes post-DriverEntry cleanup.
#define KC_ERASE_PE_HEADER() \
    (::kernelcloak::security::detail::erase_pe_headers())

#else // KC_ENABLE_PE_ERASE disabled

#define KC_ERASE_PE_HEADER() (false)

#endif // KC_ENABLE_PE_ERASE

