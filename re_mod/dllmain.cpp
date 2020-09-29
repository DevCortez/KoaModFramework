// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "rapidjson/document.h"
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>

using namespace rapidjson;

bool LoadMod(std::string path) {
    bool result = true;
    printf("Reading mod %s\n", path.c_str());

    if (path.find(".json") != std::string::npos) {
        // Read the file
        std::fstream file(path);
        std::string file_content((std::istreambuf_iterator<char>(file)), 
                (std::istreambuf_iterator<char>()));

        // Parse the json
        Document document;
        document.Parse(file_content.c_str());
    }
    else if (path.find(".dll") != std::string::npos) {
        LoadLibraryA(path.c_str());
    }
    
    return result;
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

