// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "rapidjson/document.h"
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>

using namespace rapidjson;

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

        for (int index = 0; index < patches.Size(); index++) {
            const Value& element = patches[index];
            
            // Validate json
            if (!element["description"].IsString()) {
                printf("\tInvalid description\n");
                return false;
            }
            if (!element["patch"].IsString()) {
                printf("\tInvalid patch\n");
                return false;
            }
            if (!element["signature"].IsString()) {
                printf("\tInvalid signature\n");
                return false;
            }
            std::map<std::string, std::tuple<unsigned int, unsigned int>> vars;

            if (element.HasMember("vars"))
            {
                if (!element["vars"].IsObject()) {
                    printf("\tInvalid vars\n");
                    return false;
                }

                for (Value::ConstMemberIterator variable = element["vars"].MemberBegin();
                    variable != element["vars"].MemberEnd();
                    variable++) {

                    std::string variable_name = variable->name.GetString(); 
                    const Value& variable_buffer = element["vars"][variable_name.c_str()];
                    unsigned int variable_value = variable_buffer[0].GetUint();
                    unsigned int variable_size = variable_buffer[1].GetUint();

                    vars.emplace(variable_name,
                        std::tuple<unsigned int, unsigned int>(variable_value, variable_size));

                    printf("\tAdded variable %s with value %d and size %d\n", variable_name.c_str(), 
                        variable_value, variable_size);
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

                    auto [value, size] = vars[variable_name];
                    for (int i = 0; i < size; i++) {
                        patch.push_back((value >> (8 * i)) & 0xff);
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

            for (auto x : patch) {
                printf("%02X", x);
            }

            printf("\n-- PATCH DEBUG\n\n");
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

