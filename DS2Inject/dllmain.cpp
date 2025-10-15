// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"


// DS2 Auto-Equip DLL skeleton (x64)
// ----------------------------------
// Purpose: pattern-scan for a target function in DarkSoulsII.exe, install a hook with MinHook,
// call the original, then read the written itemId from memory and call TryAutoEquipForItem.
//
// IMPORTANT:
// - This is a skeleton for development and debugging. It WILL need address/AoB values
// discovered by you with Cheat Engine (place them into the AOB_PATTERN constant below).
// - You must compile as x64 DLL (Visual Studio) and link against MinHook.
// - Use offline/copy of your game for testing.
//
// Minimal dependencies:
// - MinHook (https://github.com/TsudaKageyu/minhook)
// - Visual Studio (MSVC) x64 toolset
//
// Build steps (summary):
// 1) Create new Visual C++ Project -> Dynamic Library (DLL) -> set Platform to x64.
// 2) Add this .cpp file to the project. Add MinHook include/lib to project settings.
// 3) Set Runtime Library to Multi-threaded DLL (/MD).
// 4) Link with MinHook.lib (or add MinHook sources directly to the project).
// 5) Build Release/x64.
//
// Injection (test):
// - Use a trusted injector (Process Hacker, custom CreateRemoteThread+LoadLibrary program), or
// use Cheat Engine's "Inject DLL" feature if you prefer.
// - Start game, attach injector to DarkSoulsII.exe, inject the built DLL.
// - Check logs (OutputDebugString via DebugView or file written to disk)
//
// Disclaimer: this code is provided as a development aid. Use only offline.


#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include "Include/MinHook.h" // include MinHook header (put MinHook in include path)
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")


// ------------------ CONFIG ------------------
// Default AoB taken from your CE disassembly. Replace if needed.
static const unsigned char AOB_PATTERN[] = {
0x49,0x0F,0xBF,0xD0, // movsx rdx, r8w
0x48,0x03,0xD2, // add rdx, rdx
0x66,0x89,0x44,0xD1,0x08, // mov [rcx+rdx*8+08], ax
0xC3 // ret
};
static const char AOB_MASK[] = "xxxxxxxxxxxxx"; // 13 bytes exact match


// If you prefer, put a fixed absolute RVA (uint64_t) here instead of AOB scanning.
// ------------------ END CONFIG ------------------


// Typedef for original function. We use a generic __fastcall with rcx/rdx/r8/r9 parameters.
//using t_orig_func = void(__fastcall*)(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9);
//static t_orig_func orig_func = nullptr;

//typedef void(__fastcall* OriginalFuncType)(void* rcx, void* rdx, uint32_t r8, uint32_t r9);
//static OriginalFuncType orig_func = nullptr;


// Helper: write debug message to file (append)
static void WriteLog(const char* fmt, ...) {
    char buf[1024];
    va_list va;
    va_start(va, fmt);
    vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, va);
    va_end(va);


    OutputDebugStringA(buf);


    FILE* f = nullptr;
    if (fopen_s(&f, "F:\\C++\\DS2Inject\\DS2Inject\\ds2_autoequip_log.txt", "a") == 0 && f) {
        fprintf(f, "%s\n", buf);
        fclose(f);
    }
}

static void ClearLog() {
    FILE* f = nullptr;
    if (fopen_s(&f, "F:\\C++\\DS2Inject\\DS2Inject\\ds2_autoequip_log.txt", "w") == 0 && f) {
        fclose(f);
        WriteLog("");
    }
    else {
        OutputDebugStringA("Failed to clear log file");
    }
}

// Simple pattern scan in module memory (search only in DarkSoulsII.exe module)
static uintptr_t PatternScanModule(const char* moduleName, const unsigned char* pattern, const char* mask) {
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) return 0;

    // Получаем базовый адрес модуля и размер через GetModuleInformation
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) {
        // fallback: попытка вычислить через PE headers (если GetModuleInformation не сработал)
        uintptr_t base = (uintptr_t)hMod;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        size_t size = nt->OptionalHeader.SizeOfImage;
        size_t patternLen = strlen(mask);
        for (size_t i = 0; i < size - patternLen; ++i) {
            bool found = true;
            for (size_t j = 0; j < patternLen; ++j) {
                if (mask[j] != '?' && pattern[j] != *(unsigned char*)(base + i + j)) {
                    found = false; break;
                }
            }
            if (found) return base + i;
        }
        return 0;
    }

    uintptr_t base = (uintptr_t)modInfo.lpBaseOfDll;
    size_t size = (size_t)modInfo.SizeOfImage;
    size_t patternLen = strlen(mask);

    for (size_t i = 0; i < size - patternLen; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternLen; ++j) {
            if (mask[j] != '?' && pattern[j] != *(unsigned char*)(base + i + j)) {
                found = false; break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

// Helper: read uint16_t safely
static uint16_t ReadU16(uint64_t addr) {
    uint16_t val = 0;
    __try {
        val = *(uint16_t*)(addr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        WriteLog("ReadU16: exception reading %p", (void*)addr);
    }
    return val;
}

// Your auto-equip logic stub. Replace/implement with actual mapping itemId->type and equip calls.
static void TryAutoEquipForItem(uint64_t playerPtr, uint64_t slotIndex, uint16_t itemId) {
    // Example: log and no-op
    WriteLog("TryAutoEquip: player=%p slot=%llu itemId=%u", (void*)playerPtr, (unsigned long long)slotIndex, (unsigned)itemId);


    // TODO: Determine item type from itemId (weapon/armor/ring). Use Param files or community tables.
    // TODO: Find and call the game's internal equip function, or write to equipment slots safely.
}

// The function uses x64 fastcall convention
// We define it with the parameters we know it uses
typedef void(__fastcall* ItemPickupFuncType)(void* playerObj, void* itemData, uint32_t unknown1, uint32_t unknown2);
static ItemPickupFuncType orig_func = nullptr;


void __fastcall HookedPickupFunc(void* playerObj, void* itemData, uint32_t unknown1, uint32_t unknown2) {
    // itemData is the RDX parameter, which contains the item structure
    if (itemData) {
        uint32_t itemId = *(uint32_t*)((uintptr_t)itemData + 4);
        WriteLog("Picked up item: 0x%08X", itemId);

        // Add your auto-equip logic here
        
    }

    // Call the original function with all parameters
    orig_func(playerObj, itemData, unknown1, unknown2);
}

// Our hook function MUST match the calling convention and parameters
void __fastcall HookedFunc(void* playerObj, void* itemData, uint32_t itemCount, uint32_t unknown2) {
    if (!itemData || itemCount == 0) {
        WriteLog("No items to process");
        orig_func(playerObj, itemData, itemCount, unknown2);
        return;
    }

    WriteLog("Pickup: %d items", itemCount);

    // Process all items
    for (uint32_t i = 0; i < itemCount; i++) {
        uint8_t* itemPtr = (uint8_t*)itemData + (i * 0x10);
        uint32_t itemId = *(uint32_t*)(itemPtr + 4);

        WriteLog("  Item %d: ID=0x%08X", i, itemId);

        // Your auto-equip decision logic

    }

    // Call original function to handle actual pickup
    orig_func(playerObj, itemData, itemCount, unknown2);
}


// Setup MinHook and create the hook
static bool SetupHook() {
    WriteLog("SetupHook: scanning for AoB...");

    HMODULE moduleBase = GetModuleHandleA("DarkSoulsII.exe");

    // Hook at the actual function start (1A7475)
    uintptr_t target = (uintptr_t)moduleBase + 0x1A7475;

    // Verify the function prologue
    unsigned char expected_prologue[] = { 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x30 };
    if (memcmp((void*)target, expected_prologue, sizeof(expected_prologue)) != 0) {
        WriteLog("Function prologue doesn't match!");
        return false;
    }

    WriteLog("Hooking item pickup function at: %p", (void*)target);

    if (MH_Initialize() != MH_OK) {
        WriteLog("MH_Initialize failed");
        return false;
    }


    // Create hook on target (hook the function start)
    if (MH_CreateHook((LPVOID)target, &HookedFunc, reinterpret_cast<LPVOID*>(&orig_func)) != MH_OK) {
        WriteLog("MH_CreateHook failed");
        return false;
    }


    if (MH_EnableHook((LPVOID)target) != MH_OK) {
        WriteLog("MH_EnableHook failed");
        return false;
    }


    WriteLog("Hook installed successfully.");
    return true;
}


// Cleanup
static void RemoveHook() {
    WriteLog("DS2 AutoEquip DLL detched, removing hook...");
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        ClearLog();
        DisableThreadLibraryCalls(hModule);
        // Create a thread to run initialization so we don't block DllMain
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)[](LPVOID)->DWORD {
            WriteLog("DS2 AutoEquip DLL loaded, waiting 2s for module...\n");
            //Sleep(2000);
            SetupHook();
            return 0;
        }, nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        RemoveHook();
        break;
    }
    return TRUE;
}
