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

            while (signature_string.length() > 0) {
                if (signature_string[0] == '?') {
                    // Anything bigger than a byte is a mask
                    signature.push_back(0xFFFFFFFF);
                    signature_string.erase(0, 2);
                }
                else {
                    unsigned int value = std::stoul(signature_string.substr(0, 2),
                        nullptr, 16);
                    signature.push_back(value);
                    signature_string.erase(0, 2);
                }
            }

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

