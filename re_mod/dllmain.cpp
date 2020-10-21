// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"


using namespace rapidjson;

typedef int (*lua_CFunction) (int state);

// Structs
typedef struct luaL_Reg {
    const char* name;
    lua_CFunction func;
} luaL_Reg;


// Globals
int lua_state = 0;
std::map<std::string, std::vector<std::string>> lua_scripts;

// Constants
const auto NEW_STATE_HOOK_SIGNATURE = "8B4708FF88DC0200008BC75F5E5D5B59";
const auto LUAL_LOADFILE = "8B442408508B4424088B480881C1A802";
const auto REQUIRE_HOOK_RETURN = "E8????????5E5BB8010000005F83C478C36A3D";
const auto LUA_CALL = "8B44240C8B4C24088B5424046A00505152E8????????83C410C3CCCCCCCCCCCC558BEC83EC6C";
const auto FREE_STRING = "51578BF98B0785C07468536A248D4C240C32DB";
const auto LUA_GETTOP = "8B4C24048B41242B4128C1F803C3CCCC8B4C24048B41242B";
const auto LUA_TOSTRING = "8B4C240881F9F0D8FFFF7E3585C97E1D8B4424048B50288D4CCAF83B4824731E6A005150E8";
const auto LUA_REGISTER = "8B44240C8B4C2408568B7424086A006A005051E8";
const auto LUA_ISSTRING = "8B4424083DF0D8FFFF7E3D85C07E258B4C24048B51288D44C2F83B412473268B0083E00F83F804740583F8037517B801000000C3790F8B4C24048B51248D04C23B412873DA33C0C3750E8B4424048B400805E4000000EBC73DEED8FFFF75098B";

// Game's functions
void (__cdecl *ki_lua_pushstring)(int state, const char* str) = nullptr;
int (__cdecl *luaL_loadfile)(int state, const char* filename) = nullptr;
void (__cdecl *lua_call)(int state, int nargs, int nresults) = nullptr;
void* free_string = nullptr;
int (__cdecl *ki_lua_gettop)(int state) = nullptr;
const char* (__cdecl *ki_lua_tostring)(int state, int index) = nullptr;
void (__cdecl *luaL_register)(int state, const char* libname, const luaL_Reg* r) = nullptr;
int (__cdecl *ki_lua_isstring)(int state, int index) = nullptr;

void suspend_game() {
    auto current_thread = GetCurrentThreadId();
    auto current_process = GetCurrentProcessId();
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(h, &te)) {
            do {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) {
                    
                    if (te.th32ThreadID != current_thread && te.th32OwnerProcessID == current_process) {
                        // Suspend game's thread
                        auto thread_handle = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
                        if (thread_handle) {
                            SuspendThread(thread_handle);
                            CloseHandle(thread_handle);
                        }
                    }
                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
}

void resume_game() {
    auto current_thread = GetCurrentThreadId();
    auto current_process = GetCurrentProcessId();

    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(h, &te)) {
            do {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) {

                    if (te.th32ThreadID != current_thread && te.th32OwnerProcessID == current_process) {
                        // Resume game's thread
                        auto thread_handle = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
                        if (thread_handle) {
                            ResumeThread(thread_handle);
                            CloseHandle(thread_handle);
                        }
                    }
                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
}

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
    DWORD start_address = (DWORD)GetModuleHandle(0);

    std::vector<std::future<int>> threads;

    for (DWORD offset = 0; offset < 0x00F3A000-signature.size(); offset+=0x100000) {
        threads.push_back(std::async(std::launch::async, [](std::vector<unsigned int> sig, DWORD address, DWORD size)->int {
            int result = 0;
            bool valid = true;
            bool critical_failure = false;

            for (DWORD offset = 0; offset < size - sig.size(); offset++) {
                bool found = true;

                try {
                    for (DWORD byte_offset = 0; byte_offset < sig.size(); byte_offset++) {
                        if (sig[byte_offset] > 0xFF) {
                            continue;
                        }

                        if (*(BYTE*)(offset + address + byte_offset) != sig[byte_offset]) {
                            found = false;
                            break;
                        }
                    }
                }
                catch(std::exception e){
                    // Most likely hit a protected memory region
                    critical_failure = true;
                }

                if (critical_failure) {
                    return 0;
                }

                if (found) {
                    return address + offset;
                }
            }

            return 0;
            }, signature, offset + start_address, 0x200000));
    }
    
    for (auto& thread : threads) {
        DWORD result = thread.get();

        if (result) {
            printf("Found signature @ %08X\n", result);
            return (void*)result;
        }
    }

    printf("Failed getting signature\n");
    return 0;
}

static int fake_print(int state) {
    int nargs = ki_lua_gettop(state);

    for (int i = 1; i <= nargs; i++) {
        if (ki_lua_isstring(lua_state, i)) {
            auto buffer = ki_lua_tostring(state, i);
            std::cout << "[LUA]\t" << buffer;
        }
    }

    std::cout << std::endl;

    return 0;
}

static const struct luaL_Reg modfuncs[] =
{
    { "print", fake_print},
    { NULL, NULL }
};

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

        // Fucking ugly, find a way to move elsewhere idk
        luaL_register(lua_state, "_G", modfuncs);

        // Do stuff with the script
        for (auto script : lua_scripts[current_file]) {
            printf("Found script %s for %s\n", script.c_str(), current_file.c_str());
            int load_result = luaL_loadfile(lua_state, script.c_str());
            if (load_result == 0) {
                try {
                    lua_call(lua_state, 0, 0);
                    printf("Loaded custom script %s\n", script.c_str());
                }
                catch (const std::exception& e) {
                    printf("Failed loading module %s with error\n\t %s\n", script.c_str(), e.what());
                }
            }
            else {
                printf("Failed loading module %s with code %08X\n", script.c_str(), load_result);
            }
        }

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
    std::vector<unsigned int> signature;;
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
    std::vector<unsigned int> signature;

    signature = create_signature_from_string(LUAL_LOADFILE);
    luaL_loadfile = (int(__cdecl*)(int state, const char* filename))LookupSignature(signature);

    signature = create_signature_from_string(LUA_CALL);
    lua_call = (void(__cdecl*)(int state, int nargs, int nresults))LookupSignature(signature);

    signature = create_signature_from_string(FREE_STRING);
    free_string = LookupSignature(signature);

    signature = create_signature_from_string(LUA_GETTOP);
    ki_lua_gettop = (int(__cdecl*)(int state))LookupSignature(signature);

    signature = create_signature_from_string(LUA_TOSTRING);
    ki_lua_tostring = (const char* (__cdecl*)(int state, int index))LookupSignature(signature);

    signature = create_signature_from_string(LUA_REGISTER);
    luaL_register = (void(__cdecl*)(int state, const char* libname, const luaL_Reg * r))LookupSignature(signature);

    signature = create_signature_from_string(LUA_ISSTRING);
    ki_lua_isstring = (int(__cdecl*)(int state, int index))LookupSignature(signature);
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

        if (document.HasMember("scripts")) {
            const Value& scripts = document["scripts"];

            if (!scripts.IsArray())
                return false;

            for (int index = 0; index < scripts.Size(); index++) {
                const Value& element = scripts[index];

                std::string script_trigger = element["trigger"].GetString();
                std::string script_path = element["path"].GetString();

                lua_scripts[script_trigger].push_back(script_path);
            }
        }
        
        if (document.HasMember("patches")) {
            const Value& patches = document["patches"];

            if (!patches.IsArray())
                return false;

            for (int index = 0; index < patches.Size(); index++) {
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

void Initialize() {    
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
            printf("Something went wrong loading %s\n", entry.path().string().c_str());
        }
    }

    while (true) {
        std::string user_input;
        std::cin >> user_input;
        std::fstream lua_placeholder("_temp.lua", std::fstream::out);
        lua_placeholder << user_input;
        lua_placeholder.close();
        suspend_game();

        luaL_loadfile(lua_state, "_temp.lua");
        try {
            lua_call(lua_state, 0, 0);

            /*
            int count = ki_lua_gettop(lua_state);

            for (int i = 0; i < count; i++) {
                auto buffer = ki_lua_tostring(lua_state, i);
                std::cout << buffer;
            }

            std::cout << std::endl;*/
        }
        catch (std::exception e) {
            printf("Error executing command %s\n", e.what());
        }

        resume_game();
    }
    return ;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)&Initialize, 0, 0, nullptr);
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

