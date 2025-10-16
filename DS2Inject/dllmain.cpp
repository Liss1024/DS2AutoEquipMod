// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdint>
#include <inttypes.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include "Include/MinHook.h"
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")



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

// Our hook function MUST match the calling convention and parameters
void __fastcall HookedFunc(void* playerObj, void* itemData, uint32_t itemCount, uint32_t unknown2) {
    if (!itemData || itemCount == 0) {
        WriteLog("No items to process");
        orig_func(playerObj, itemData, itemCount, unknown2);
        return;
    }

    WriteLog("Pickup: %d items", itemCount);
    
    WriteLog("PlayerObj: %p", playerObj);

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


constexpr uintptr_t UI_FUNC_RTE_OFFSET = 0x0012793;
constexpr uintptr_t UI_FUNC_GHIDRA_OFFSET = 0x00127A0;
//FUN_140026e70 from Ghidra
constexpr uintptr_t DISPATCH_FUNC_OFFSET = 0x0026E70;

// ----------------- Utilities -----------------
static void hex_dump_and_log(const void* addr, size_t len, const char* prefix = "")
{
    const unsigned char* p = (const unsigned char*)addr;
    size_t i = 0;
    size_t row = 16;
    char buf[512];
    for (; i < len; i += row) {
        int n = snprintf(buf, sizeof(buf), "%s%08zx: ", prefix, i);
        for (size_t j = 0; j < row && i + j < len; ++j) {
            n += snprintf(buf + n, sizeof(buf) - n, "%02X ", p[i + j]);
        }
        // ASCII part
        n += snprintf(buf + n, sizeof(buf) - n, " |");
        for (size_t j = 0; j < row && i + j < len; ++j) {
            unsigned char c = p[i + j];
            n += snprintf(buf + n, sizeof(buf) - n, "%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        n += snprintf(buf + n, sizeof(buf) - n, "|");
        WriteLog("%s", buf);
    }
}

// Safe memory read with SEH protection
template<typename T>
static bool safe_read_ptr(void* base, size_t offset, T& out)
{
    bool ok = false;
    __try {
        T* ptr = (T*)((uintptr_t)base + offset);
        out = *ptr;
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

static bool safe_read_bytes(void* addr, void* buf, size_t len)
{
    bool ok = false;
    __try {
        memcpy(buf, addr, len);
        ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

// ----------------- Originals typedefs -----------------
typedef void(__fastcall* tUIFunc)(uint64_t param1 /*RCX*/);
static tUIFunc orig_ui_func = nullptr;

// FUN_140026e70 signature: void FUN_140026e70(longlong param_1,longlong *param_2)
// => RCX = param_1, RDX = param_2 (pointer to pointer)
typedef void(__fastcall* tDispatchFunc)(uint64_t param1 /*RCX*/, uint64_t* param2 /*RDX*/);
static tDispatchFunc orig_dispatch_func = nullptr;

// ----------------- Hooks -----------------
// 
// ----------------- FUN_140094a40 entry -----------------
void __fastcall Hooked_UI_Func(uint64_t rcx_param1)
{
    WriteLog("[UI_HOOK] FUN_140094a40 called. RCX(param_1) = 0x%016" PRIx64, rcx_param1);

    if (rcx_param1 != 0) {
        
        unsigned char tmp[0x40];
        if (safe_read_bytes((void*)rcx_param1, tmp, sizeof(tmp))) {
            WriteLog("[UI_HOOK] Memory at RCX (first 64 bytes):");
            hex_dump_and_log(tmp, sizeof(tmp), "  mem: ");
        }
        else {
            WriteLog("[UI_HOOK] Failed to read memory at RCX");
        }
    }
    else {
        WriteLog("[UI_HOOK] RCX == NULL");
    }


    if (orig_ui_func) {
        orig_ui_func(rcx_param1);
    }
}

static bool looks_like_ptr(uint64_t v) {

    if (v == 0) return false;

    return (v >= 0x000010000000ULL && v <= 0x00007fffffffffffULL);
}

static void scan_event_for_itemid(uint64_t event_ptr, uint32_t targetItemId32 = 0, uint64_t targetItemId64 = 0)
{
    WriteLog("[SCAN] Scanning event 0x%016" PRIx64, event_ptr);
    for (size_t off = 0; off <= 0x70; off += 8) {
        uint64_t val = 0;
        if (!safe_read_ptr<uint64_t>((void*)event_ptr, off, val)) continue;
        if (!looks_like_ptr(val)) continue;
        WriteLog("[SCAN] field +0x%02zx => ptr 0x%016" PRIx64, off, val);

        unsigned char buf[0x80];
        if (!safe_read_bytes((void*)val, buf, sizeof(buf))) {
            WriteLog("[SCAN] Cannot read memory at 0x%016" PRIx64, val);
            continue;
        }
        WriteLog("[SCAN] Dump at 0x%016" PRIx64 " (first 128 bytes):", val);
        hex_dump_and_log(buf, sizeof(buf), "  scan: ");

        // Look for 32-bit little endian targetItemId32
        if (targetItemId32 != 0) {
            for (size_t i = 0; i + 4 <= sizeof(buf); ++i) {
                uint32_t v = *(uint32_t*)(buf + i);
                if (v == targetItemId32) {
                    WriteLog("[SCAN] Found 32-bit itemId 0x%08X at 0x%016" PRIx64 " + 0x%zx (field +0x%02zx)", v, val, i, off);
                }
            }
        }
        // Look for 64-bit little endian targetItemId64
        if (targetItemId64 != 0) {
            for (size_t i = 0; i + 8 <= sizeof(buf); ++i) {
                uint64_t v = *(uint64_t*)(buf + i);
                if (v == targetItemId64) {
                    WriteLog("[SCAN] Found 64-bit itemId 0x%016" PRIx64 " at 0x%016" PRIx64 " + 0x%zx (field +0x%02zx)", v, val, i, off);
                }
            }
        }
    }
}
// ----------------- Hook Dispatch (FUN_140026e70) -----------------
void __fastcall Hooked_Dispatch(uint64_t param1_rcx, uint64_t* param2_rdx)
{
    WriteLog("\n[DISPATCH_HOOK] >>> FUN_140026e70 called");
    WriteLog("  RCX (param1) = 0x%016" PRIx64, param1_rcx);
    WriteLog("  RDX (param2 ptr) = 0x%016" PRIx64, (uint64_t)param2_rdx);

    uint64_t event_obj_ptr = 0;
    if (param2_rdx && safe_read_ptr<uint64_t>(param2_rdx, 0, event_obj_ptr))
        WriteLog("  *param2 (event_obj_ptr) = 0x%016" PRIx64, event_obj_ptr);
    else
        WriteLog("  *param2 (event_obj_ptr) = <invalid>");

    // ============================
    // param1 check
    // ============================

    uint64_t item_ptr = 0;
    uint32_t slot_id = 0;

    // param1 + 0x2008 ? slot id (int32)
    if (safe_read_ptr<uint32_t>((void*)param1_rcx, 0x2008, slot_id))
        WriteLog("  [param1+0x2008] slot_id = 0x%08X (%u)", slot_id, slot_id);
    else
        WriteLog("  [param1+0x2008] slot_id = <unreadable>");

    // param1 + 0x2028 ? qword ptr на предмет
    if (safe_read_ptr<uint64_t>((void*)param1_rcx, 0x2028, item_ptr))
        WriteLog("  [param1+0x2028] item_ptr = 0x%016" PRIx64, item_ptr);
    else
        WriteLog("  [param1+0x2028] item_ptr = <unreadable>");

    // Maybe this is a pointer to some struct?
    if (item_ptr) {
        uint64_t item_vtable = 0;
        uint32_t item_id = 0;

        safe_read_ptr<uint64_t>((void*)item_ptr, 0x0, item_vtable);
        safe_read_ptr<uint32_t>((void*)item_ptr, 0x10, item_id);

        WriteLog("    [item_ptr+0x00] vtable = 0x%016" PRIx64, item_vtable);
        WriteLog("    [item_ptr+0x10] possible item_id = 0x%08X (%u)", item_id, item_id);

        // We are trying to match ID of a Thief Broken Sword, I was equipping it
        if (item_id == 0x001053B0)
            WriteLog("    >>> MATCH: item_id == 0x001053B0 (your equipped item)");
    }


    if (event_obj_ptr) {
        uint64_t vtable = 0;
        uint32_t maybe_itemid = 0;
        uint32_t maybe_slot = 0;

        safe_read_ptr<uint64_t>((void*)event_obj_ptr, 0x0, vtable);
        safe_read_ptr<uint32_t>((void*)event_obj_ptr, 0x10, maybe_itemid);
        safe_read_ptr<uint32_t>((void*)event_obj_ptr, 0x14, maybe_slot);

        WriteLog("  [event_obj] vtable = 0x%016" PRIx64, vtable);
        WriteLog("  [event_obj+0x10] = 0x%08X (%u)", maybe_itemid, maybe_itemid);
        WriteLog("  [event_obj+0x14] = 0x%08X (%u)", maybe_slot, maybe_slot);
    }


    if (orig_dispatch_func)
        orig_dispatch_func(param1_rcx, param2_rdx);
}


// ----------------- Setup hooks -----------------
bool SetupEventLoggingHooks()
{
    WriteLog("Setting up event-logging hooks...");

    HMODULE moduleBase = GetModuleHandleA("DarkSoulsII.exe");
    if (!moduleBase) {
        WriteLog("GetModuleHandleA failed");
        return false;
    }

    uintptr_t ui_target = (uintptr_t)moduleBase + UI_FUNC_RTE_OFFSET;
    uintptr_t dispatch_target = (uintptr_t)moduleBase + DISPATCH_FUNC_OFFSET;

    WriteLog("UI hook target:      %p (module + 0x%IX)", (void*)ui_target, (uintptr_t)UI_FUNC_RTE_OFFSET);
    WriteLog("Dispatch hook target:%p (module + 0x%IX)", (void*)dispatch_target, (uintptr_t)DISPATCH_FUNC_OFFSET);

    if (MH_CreateHook((LPVOID)ui_target, &Hooked_UI_Func, reinterpret_cast<LPVOID*>(&orig_ui_func)) != MH_OK) {
        WriteLog("MH_CreateHook failed for UI function");
        return false;
    }

    if (MH_CreateHook((LPVOID)dispatch_target, &Hooked_Dispatch, reinterpret_cast<LPVOID*>(&orig_dispatch_func)) != MH_OK) {
        WriteLog("MH_CreateHook failed for Dispatch function");
        return false;
    }

    if (MH_EnableHook((LPVOID)ui_target) != MH_OK) {
        WriteLog("MH_EnableHook failed for UI function");
        return false;
    }
    if (MH_EnableHook((LPVOID)dispatch_target) != MH_OK) {
        WriteLog("MH_EnableHook failed for Dispatch function");
        return false;
    }

    WriteLog("Event-logging hooks installed.");
    return true;
}

// ----------------- Teardown -----------------
void RemoveEventLoggingHooks()
{
    HMODULE moduleBase = GetModuleHandleA("DarkSoulsII.exe");
    if (!moduleBase) return;

    MH_DisableHook(MH_ALL_HOOKS);
    MH_RemoveHook(MH_ALL_HOOKS);
    // Btw I think this is never called, check later why
    WriteLog("Event-logging hooks removed.");
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
            SetupEventLoggingHooks();
            return 0;
        }, nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        RemoveHook();
        break;
    }
    return TRUE;
}
