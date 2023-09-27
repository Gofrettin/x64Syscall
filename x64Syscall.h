#pragma once

#include <iostream>
#include <chrono>
#include <winnt.h>
#include <intrin.h>
#include <minwindef.h>

#if defined(_M_IX86)
static_assert(false, "x86 Not Supported!");
#endif

typedef struct PEB_LOADER_DATA
{
    UINT8 _PADDING_[12];
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct PEB_NEW
{
    UINT8 _PADDING_[24];
    PEB_LOADER_DATA* Ldr;
} PEB_NEW, * PPEB_NEW;

typedef struct _UNICODE_STRINGG
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRINGG;

typedef struct LOADER_TABLE_ENTRY
{
    LIST_ENTRY				InLoadOrderLinks;
    LIST_ENTRY				InMemoryOrderLinks;
    LIST_ENTRY				InInitializationOrderLinks;
    uintptr_t				DllBase;
    uintptr_t				EntryPoint;
    uint32_t				SizeOfImage;
    UNICODE_STRINGG			FullDllName;
    UNICODE_STRINGG			BaseDllName;
    uint8_t					FlagGroup[4];
    uint32_t				Flags;
    uint16_t				ObsoleteLoadCount;
    uint16_t				TlsIndex;
    LIST_ENTRY				HashLinks;
    uint32_t				TimeDateStamp;
    uintptr_t				EntryPointActivationContext;
    uintptr_t				Lock;
    uintptr_t				DdagNode;
    LIST_ENTRY				NodeModuleLink;
    uintptr_t				LoadContext;
    uintptr_t				ParentDllBase;
} LOADER_TABLE_ENTRY, * PLOADER_TABLE_ENTRY;

namespace x64Syscall
{
    namespace Hash
    {
        enum Types_t : unsigned long long
        {
            FNV_PRIME = 0x01000193,
            FNV_BASIS = 0x811C9DC5
        };

        inline constexpr unsigned int GetStringLength(const char* strData)
        {
            if (!strData)
                return 0;

            unsigned int strLength = 0;
            while (strData[strLength] != '\0')
            {
                strLength++;
            }

            return strLength;
        }

        inline constexpr unsigned long long HashData(const char* dataToHash)
        {
            unsigned int strLength = GetStringLength(dataToHash);
            if (!strLength)
                return 0;

            unsigned long long outData = 0;
            for (unsigned int i = 0; i < strLength; i++)
            {
                outData = outData ^ dataToHash[i] * FNV_PRIME;
                outData *= FNV_BASIS;
            }

            return outData;
        }

        inline unsigned long long HashData(std::string dataToHash)
        {
            unsigned int strLength = dataToHash.length();
            if (!strLength)
                return 0;

            unsigned long long outData = 0;
            for (unsigned int i = 0; i < strLength; i++)
            {
                outData = outData ^ dataToHash[i] * FNV_PRIME;
                outData *= FNV_BASIS;
            }

            return outData;
        }
    }

    namespace Helper
    {
        extern "C" void* x64SyscallCallback();

        template <typename... Args>
        static inline auto CallHelper(Args... args) -> void*
        {
            auto fn = reinterpret_cast<void* (*)(Args...)>(&x64SyscallCallback);
            return fn(args...);
        }

        template <unsigned long long argc, typename>
        struct ArguementRemapper
        {
            // At least 5 params
            template<typename First, typename Second, typename Third, typename Fourth, typename... Pack>
            static auto PerformCall(unsigned int idx, First first, Second second, Third third, Fourth fourth, Pack... pack) -> void*
            {
                return CallHelper(first, second, third, fourth, idx, nullptr, pack...);
            }
        };

        template <unsigned long long Argc>
        struct ArguementRemapper<Argc, std::enable_if_t<Argc <= 4>>
        {
            // 4 or less params
            template<typename First = void*, typename Second = void*, typename Third = void*, typename Fourth = void*>
            static auto PerformCall(unsigned int idx, First first = First{}, Second second = Second{}, Third third = Third{}, Fourth fourth = Fourth{}) -> void*
            {
                return CallHelper(first, second, third, fourth, idx, nullptr);
            }
        };

        inline HMODULE GetBaseAddressOfModule(unsigned long long moduleNameHash)
        {
            // Get PEB data.
            PEB_NEW* peb = (PEB_NEW*)__readgsqword(0x60);

            if (peb == nullptr)
                return nullptr;

            PLIST_ENTRY listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
            PLOADER_TABLE_ENTRY tableEntry = nullptr;

            // Iterate each module.
            while (listEntry != &peb->Ldr->InLoadOrderModuleList && listEntry)
            {
                // Declare table.
                tableEntry = CONTAINING_RECORD(listEntry, LOADER_TABLE_ENTRY, InLoadOrderLinks);

                std::wstring wideNameString(tableEntry->BaseDllName.Buffer);
                std::string currentIteratedModuleName(wideNameString.begin(), wideNameString.end());

                // Convert string to lowercase, since all modules in memory are lowercase.
                std::transform(currentIteratedModuleName.begin(), currentIteratedModuleName.end(), currentIteratedModuleName.begin(), ::tolower);

                HMODULE base = (HMODULE)tableEntry->DllBase;

                if (Hash::HashData(currentIteratedModuleName) == moduleNameHash)
                    return (HMODULE)tableEntry->DllBase;

                // Update flink.
                listEntry = listEntry->Flink;
            }

            return nullptr;
        }
    }

    inline const unsigned int GetIndex(unsigned long long moduleNameHash, unsigned long long syscallNameHash)
    {
        unsigned char* moduleBase = reinterpret_cast<unsigned char*>(Helper::GetBaseAddressOfModule(moduleNameHash));
        if (!moduleBase)
            return 0;

        PIMAGE_DOS_HEADER dosHeader = PIMAGE_DOS_HEADER(moduleBase);
        if (!dosHeader)
            return 0;

        PIMAGE_NT_HEADERS ntHeaders = PIMAGE_NT_HEADERS(moduleBase + dosHeader->e_lfanew);
        if (!ntHeaders)
            return 0;

        PIMAGE_EXPORT_DIRECTORY expDirectory = PIMAGE_EXPORT_DIRECTORY(moduleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (!expDirectory)
            return 0;

        unsigned long long syscallAddress = 0;

        for (unsigned int i = 0; i < expDirectory->NumberOfNames; i++)
        {
            char* curName = reinterpret_cast<char*>(moduleBase + reinterpret_cast<unsigned long*>(moduleBase + expDirectory->AddressOfNames)[i]);
            if (!curName)
                continue;

            if (!((curName[0] == 'N' && curName[1] == 't') || (curName[0] == 'Z' && curName[1] == 'w')))
                continue;

            if (Hash::HashData(curName) == syscallNameHash)
            {
                unsigned short ordinal = reinterpret_cast<unsigned short*>(moduleBase + expDirectory->AddressOfNameOrdinals)[i];
                syscallAddress = reinterpret_cast<unsigned long long>(moduleBase + reinterpret_cast<unsigned long*>(moduleBase + expDirectory->AddressOfFunctions)[ordinal]);
            }
        }

        // Bad address.
        if (!syscallAddress)
            return 0;

        // Bad index.
        unsigned int syscallIndex = *(unsigned int*)(syscallAddress + 4);
        if (!syscallIndex)
            return 0;

        return syscallIndex;
    }

    template<typename Return, typename... Args>
    static inline auto Call(unsigned long long moduleName, unsigned long long syscallName, Args... args) -> Return
    {
        using ArgRemapper_t = Helper::ArguementRemapper<sizeof...(Args), void>;
        unsigned int idx = GetIndex(moduleName, syscallName);
        return (Return)ArgRemapper_t::PerformCall(idx, args...);
    }
}

#define PERFORM_SYSCALL(moduleName, functionName, type, ...) \
{ \
    static unsigned int idx = x64Syscall::GetIndex(moduleName, functionName); \
    x64Syscall::Call<type>(__VA_ARGS__); \
}

#define HASH(x) \
[&]() \
{ \
    constexpr auto outData = x64Syscall::Hash::HashData(x); \
    return outData; \
} ()
