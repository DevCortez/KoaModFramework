// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "rapidjson/document.h"
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>
#include <vector>

using namespace rapidjson;

// Globals
int lua_state = 0;

// Constants
const auto NEW_STATE_HOOK_SIGNATURE = "8B4708FF88DC0200008BC75F5E5D5B59";
const auto KI_LUA_PUSHSTRING = "8B54240885D275108B4C24048B4124891083C008894124C38BC2568D70018BFF8A084084C975F92BC6508B44240C5250E8ABFDFFFF83C40C5EC3CC";
const auto LUAL_LOADFILE = "8B442408508B4424088B480881C1A802";
const auto REQUIRE_HOOK = "508D4C241CE8????????6A018D44241C508D4C24";
const auto REQUIRE_HOOK_RETURN = "E8????????5E5BB8010000005F83C478C36A3D";
const auto LUA_CALL = "8B44240C8B4C24088B5424046A00505152E8????????83C410C3CCCCCCCCCCCC558BEC83EC6C";
const auto FREE_STRING = "51578BF98B0785C07468536A248D4C240C32DB";

// Game's functions
void (__cdecl *ki_lua_pushstring)(int state, const char* str) = nullptr;
int (__cdecl *luaL_loadfile)(int state, const char* filename) = nullptr;
void (__cdecl *lua_call)(int state, int nargs, int nresults) = nullptr;
void* free_string = nullptr;

std::vector<unsigned int> create_signature_from_string(const std::string signature) {
    std::string local_signature = signature;
    std::vector<unsigned int> result;

    while (local_signature.length() > 0) {
        if (local_signature[0] == '?') {
            // Anything bigger than a byte is a mask
            result.push_back(0xFFFFFFFF);
            local_signature.erase(0, 2);
        }
        else {
            unsigned int value = std::stoul(local_signature.substr(0, 2),
                nullptr, 16);
            result.push_back(value);
            local_signature.erase(0, 2);
        }
    }

    return result;
}

void* LookupSignature(const std::vector<unsigned int> &signature) {
    printf("Size of signature %d\n", signature.size());
    DWORD start_address = (DWORD)GetModuleHandle(0);

    for (DWORD offset = 0; offset < 0x00F3A000-signature.size(); offset++) {
        bool valid = true;

        for (DWORD byte_offset = 0; byte_offset < signature.size(); byte_offset++) {
            if (signature[byte_offset] > 0xFF) {
                continue;
            }
            
            if (*(BYTE*)(offset + start_address + byte_offset) != signature[byte_offset]) {
                valid = false;
                break;
            }
        }

        if (valid) {
            return (void*)(start_address + offset);
        }
    }

    return 0;
}

int __stdcall _new_state_hook(int state) {
    lua_state = state;
    printf("ki_kore_newstate created 0x%08X state\n", state);
    return state;
}

void hook_new_state() {
    /*
    * This roughly translates to
    * push eax
    * call _new_state_hook
    * retn
    */
    std::vector<unsigned int> signature = create_signature_from_string(NEW_STATE_HOOK_SIGNATURE);
    void* address = LookupSignature(signature);
    address = (LPVOID)((DWORD)address + 16); // Offset for the patch
    BYTE opcode = 0x50;
    DWORD placeholder;
    WriteProcessMemory((HANDLE)-1, address, &opcode, 1, &placeholder);
    opcode = 0xe8;
    WriteProcessMemory((HANDLE)-1, (LPVOID)((DWORD)address + 1), &opcode, 1, &placeholder);
    DWORD calculated_address = (DWORD)&_new_state_hook - (DWORD)address - 5 - 1;
    WriteProcessMemory((HANDLE)-1, (LPVOID)((DWORD)address + 2), &calculated_address, 4, &placeholder);
    opcode = 0xc3;
    WriteProcessMemory((HANDLE)-1, (LPVOID)((DWORD)address + 6), &opcode, 1, &placeholder);

    printf("Hooked ki_kore_newstate\n");
}

char* _file;
std::vector<std::string> files_being_loaded;
DWORD _require_hook_return = 0;
bool require_hook_enabled = true;



void _stdcall _require_hook_end_process(char* pFile) {
    if (require_hook_enabled) {
        require_hook_enabled = false;
        std::string current_file(pFile);
        printf("Finished loading script %s\n", current_file.c_str());

        // Do stuff with the script
        //*
        if (current_file.compare("ConsumableManager") == 0) {
            int result = luaL_loadfile(lua_state, ".\\mods\\name_winz.lua");
            printf("Loaded script with result %x\n", result);
            if (result == 0) {
                printf("Doing luacall on state %X\n", lua_state);
                lua_call(lua_state, 0, 0);
                printf("Sucessful\n");
            }
        }
        //*/

        require_hook_enabled = true;
    }
}

__declspec(naked) void _require_hook_end() {
    _asm {
        pushad
        mov ecx, [ecx]
        push [ecx]
        call _require_hook_end_process
        popad
        call free_string
        pop esi
        pop ebx
        mov eax, 1
        pop edi
        add esp, 0x78
        ret
    }
}

void hook_require() {
    std::vector<unsigned int> signature = create_signature_from_string(REQUIRE_HOOK);
    void* address;
    BYTE opcode;
    DWORD placeholder;

    signature = create_signature_from_string(REQUIRE_HOOK_RETURN);
    address = LookupSignature(signature);
    opcode = 0xe9;
    WriteProcessMemory((HANDLE)-1, address, &opcode, 1, &placeholder);
    DWORD calculated_address = (DWORD)&_require_hook_end - (DWORD)address - 5;
    WriteProcessMemory((HANDLE)-1, (LPVOID)((DWORD)address + 1), &calculated_address, 4, &placeholder);
}

void find_game_functions() {
    std::vector<unsigned int> signature = create_signature_from_string(KI_LUA_PUSHSTRING);
    ki_lua_pushstring = (void (*__cdecl)(int state, const char* str))LookupSignature(signature);
    signature = create_signature_from_string(LUAL_LOADFILE);
    luaL_loadfile = (int(__cdecl*)(int state, const char* filename))LookupSignature(signature);
    signature = create_signature_from_string(LUA_CALL);
    lua_call = (void(__cdecl*)(int state, int nargs, int nresults))LookupSignature(signature);
    signature = create_signature_from_string(FREE_STRING);
    free_string = LookupSignature(signature);
}

void WritePatch(const void* patch_address, const std::vector<unsigned int> &patch) {
    for (int i = 0; i < patch.size(); i++) {
        if (patch[i] > 0xFF) {
            continue;
        }

        DWORD placeholder;
        WriteProcessMemory((HANDLE)-1, (LPVOID)((DWORD)patch_address + i), 
            &patch[i], 1, &placeholder);
    }
}

bool LoadMod(std::string path) {
    printf("Reading mod %s\n", path.c_str());

    if (path.find(".json") != std::string::npos) {
        // Read the file
        std::fstream file(path);
        std::string file_content((std::istreambuf_iterator<char>(file)), 
                (std::istreambuf_iterator<char>()));

        // Parse the json
        Document document;
        document.Parse(file_content.c_str());
        const Value& patches = document["patches"];

        if (!patches.IsArray())
            return false;

        for (unsigned int index = 0; index < patches.Size(); index++) {
            const Value& element = patches[index];
            
            // Validate json
            if (!element["description"].IsString()) {
                printf("Invalid description\n");
                return false;
            }
            if (!element["patch"].IsString()) {
                printf("Invalid patch\n");
                return false;
            }
            if (!element["signature"].IsString()) {
                printf("Invalid signature\n");
                return false;
            }
            std::map<std::string, std::tuple<double, unsigned int>> vars;

            if (element.HasMember("vars"))
            {
                if (!element["vars"].IsObject()) {
                    printf("Invalid vars\n");
                    return false;
                }

                for (Value::ConstMemberIterator variable = element["vars"].MemberBegin();
                    variable != element["vars"].MemberEnd();
                    variable++) {

                    std::string variable_name = variable->name.GetString(); 
                    const Value& variable_buffer = element["vars"][variable_name.c_str()];
                    double variable_value = variable_buffer[0].GetDouble();
                    unsigned int variable_type = variable_buffer[1].GetUint();
                    vars.emplace(variable_name,
                        std::tuple<double, unsigned int>(variable_value, variable_type));

                    printf("Added variable %s with value %f and type %d\n", variable_name.c_str(), 
                        variable_value, variable_type);
                }
            }

            std::string description = element["description"].GetString();
            std::string signature_buffer = element["signature"].GetString();
            std::string patch_buffer = element["patch"].GetString();

            std::string signature_string;
            std::string patch_string;

            // Clean up strings
            for (const char character : signature_buffer) {
                if (character != ' ') {
                    signature_string += character;
                }
            }

            for (const char character : patch_buffer) {
                if (character != ' ') {
                    patch_string += character;
                }
            }
            printf("DEBUG %s %s\n", signature_string.c_str(), patch_string.c_str());

            std::vector<unsigned int> signature;
            std::vector<unsigned int> patch;

            while (patch_string.length() > 0) {
                if (patch_string[0] == '[') {
                    // Is a variable
                    unsigned int name_end = patch_string.find(']');
                    std::string variable_name = patch_string.substr(1,
                        name_end - 1);

                    auto [double_value, variable_type] = vars[variable_name];
                    unsigned int int_value = double_value;
                    float float_value = double_value;

                    switch (variable_type)
                    {
                        case 1:
                            patch.push_back(int_value & 0xff);
                            break;
                        case 2:
                            for (int i = 0; i < 2; i++) {
                                patch.push_back((int_value >> (8 * i)) & 0xff);
                            }
                            break;
                        case 3:
                            for (int i = 0; i < 4; i++) {
                                patch.push_back((int_value >> (8 * i)) & 0xff);
                            }
                            break;
                        case 4:
                            for (int i = 0; i < sizeof(float); i++) {
                                patch.push_back((*(int*)(&float_value) >> (8 * i)) & 0xff);
                            }
                            break;
                        case 5:
                            for (int i = 0; i < sizeof(double); i++) {
                                patch.push_back((*(INT64*)(&double_value) >> (8 * i)) & 0xff);
                            }
                            break;
                    default:
                        break;
                    }

                    patch_string.erase(0, name_end + 1);
                }
                else if (patch_string[0] == '?') {
                    // Anything bigger than a byte is a mask
                    patch.push_back(0xFFFFFFFF);
                    patch_string.erase(0, 2);
                }
                else {
                    // Is a normal value
                    unsigned int value = std::stoul(patch_string.substr(0, 2), 
                        nullptr, 16);
                    patch.push_back(value);
                    patch_string.erase(0, 2);
                }
            }

            signature = create_signature_from_string(signature_string);

            // Look for the signature in the memory
            void* address = LookupSignature(signature);
            if (address != 0) {
                printf("Address found @ %x\n", (int)address);
                WritePatch(address, patch);
            }
            else {
                return false;
            }
        }
    }
    else if (path.find(".dll") != std::string::npos) {
        auto module_base = LoadLibraryA(path.c_str());

        if (module_base == NULL) {
            printf("Failed to load module %s\n", path.c_str());
            return false;
        }
        else {
            printf("Loaded module %s @ %x\n", path.c_str(), 
                (unsigned int)module_base);
        }
    }
    
    return true;
}

bool Initialize() {
    bool result = true;
    
    // Create a console window
    AllocConsole();
    FILE* placeholder;
    freopen_s(&placeholder, "CONIN$", "r", stdin);
    freopen_s(&placeholder, "CONOUT$", "w", stderr);
    freopen_s(&placeholder, "CONOUT$", "w", stdout);

    printf("Mod framework initialization\n");

    // Write them hooks
    find_game_functions();
    hook_new_state();
    hook_require();
    
    // Load them mods
    for (const auto& entry : std::filesystem::directory_iterator(".\\mods\\")) {
        if (!LoadMod(entry.path().string())) {
            result = false;
        }
    }

    return result;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            if (!Initialize()) {
                MessageBoxA(0, "The mod framework failed to load properly", "Mod framework", 0);
            }
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

