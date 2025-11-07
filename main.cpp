#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <variant>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

HANDLE processHandle = nullptr;

struct HookData
{
    uintptr_t hookAddr = 0;
    uintptr_t detourAddr = 0;
    uintptr_t valueAddr = 0;
    std::vector<int> originalBytes;
    bool active = false;
};

std::map<std::string, HookData> hooks;

namespace Game
{
    DWORD processId = 0;
    HMODULE module = nullptr;
    uintptr_t modBaseAddr = 0;
    SIZE_T modBaseSize = 0;

    DWORD GetProcessID(const char* processName)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 entry = { sizeof(entry) };

        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        if (Process32First(snapshot, &entry))
        {
            do
            {
                if (strcmp(entry.szExeFile, processName) == 0)
                {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    HANDLE GetProcessByName(const char* name)
    {
        DWORD pid = GetProcessID(name);
        if (pid != 0)
        {
            processId = pid;
            return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        }
        return nullptr;
    }

    HMODULE GetModule(HANDLE handle)
    {
        DWORD bytesNeeded;
        HMODULE modules[1024];

        if (EnumProcessModules(handle, modules, sizeof(modules), &bytesNeeded))
        {
            for (unsigned int i = 0; i < (bytesNeeded / sizeof(HMODULE)); i++)
            {
                TCHAR moduleName[MAX_PATH];
                if (GetModuleFileNameEx(handle, modules[i], moduleName, sizeof(moduleName) / sizeof(TCHAR)))
                {
                    std::string name = moduleName;
                    if (name.find("Minecraft.Windows.exe") != std::string::npos)
                        return modules[i];
                }
            }
        }
        return nullptr;
    }

    bool Initialize()
    {
        if (processHandle)
        {
            CloseHandle(processHandle);
            processHandle = nullptr;
        }

        processHandle = GetProcessByName("Minecraft.Windows.exe");
        if (!processHandle) return false;

        module = GetModule(processHandle);
        if (!module) return false;

        MODULEINFO moduleInfo;
        if (GetModuleInformation(processHandle, module, &moduleInfo, sizeof(moduleInfo)))
        {
            modBaseAddr = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
            modBaseSize = moduleInfo.SizeOfImage;
            return true;
        }
        return false;
    }

    bool IsProcessValid()
    {
        if (!processHandle) return false;

        DWORD exitCode = 0;
        if (GetExitCodeProcess(processHandle, &exitCode))
            return exitCode == STILL_ACTIVE;

        return false;
    }
}

namespace Memory
{
    uintptr_t FindSignature(HANDLE handle, uintptr_t base, SIZE_T size, const std::vector<int>& signature)
    {
        std::vector<BYTE> memory(size);
        SIZE_T bytesRead;

        if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(base), memory.data(), size, &bytesRead))
            return 0;

        for (SIZE_T i = 0; i < bytesRead - signature.size(); i++)
        {
            bool found = true;
            for (SIZE_T j = 0; j < signature.size(); j++)
            {
                if (signature[j] != -1 && static_cast<int>(memory[i + j]) != signature[j])
                {
                    found = false;
                    break;
                }
            }

            if (found)
                return base + i;
        }

        return 0;
    }

    uintptr_t AllocateCodeCave(HANDLE handle, uintptr_t preferred, SIZE_T size)
    {
        BYTE testByte;

        for (uintptr_t i = 1; i < 2000; i++)
        {
            uintptr_t addr = preferred - (i * 0x10000);

            if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(addr), &testByte, sizeof(BYTE), nullptr))
                continue;

            LPVOID allocated = VirtualAllocEx(handle, reinterpret_cast<LPVOID>(addr), size,
                MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            if (allocated)
                return reinterpret_cast<uintptr_t>(allocated);
        }

        return 0;
    }

    void GetBytes(HANDLE handle, uintptr_t addr, std::vector<int>& bytes)
    {
        std::vector<BYTE> buffer(bytes.size());
        SIZE_T bytesRead;

        if (ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(addr), buffer.data(), buffer.size(), &bytesRead))
        {
            for (SIZE_T i = 0; i < bytesRead; i++)
                bytes[i] = static_cast<int>(buffer[i]);
        }
    }

    uintptr_t CalculateJumpOffset(uintptr_t from, uintptr_t to)
    {
        return to - (from + 5);
    }

    void SetJump(uintptr_t offset, std::vector<int>& bytes)
    {
        for (SIZE_T i = 0; i < bytes.size() - 4; i++)
        {
            if (bytes[i] == 0xE9 && bytes[i + 1] == -1 && bytes[i + 2] == -1 &&
                bytes[i + 3] == -1 && bytes[i + 4] == -1)
            {
                bytes[i + 1] = (offset >> 0) & 0xFF;
                bytes[i + 2] = (offset >> 8) & 0xFF;
                bytes[i + 3] = (offset >> 16) & 0xFF;
                bytes[i + 4] = (offset >> 24) & 0xFF;
                break;
            }
        }
    }

    bool WriteBytes(HANDLE handle, uintptr_t addr, const std::vector<int>& data)
    {
        std::vector<BYTE> bytes(data.size());
        for (SIZE_T i = 0; i < data.size(); i++)
            bytes[i] = static_cast<BYTE>(data[i]);

        SIZE_T written;
        return WriteProcessMemory(handle, reinterpret_cast<LPVOID>(addr), bytes.data(), bytes.size(), &written)
            && written == bytes.size();
    }
}

bool inject(const std::string& name, const std::vector<int>& sig, std::vector<int> hook,
    std::vector<int> detour, std::variant<int, float> defaultValue, int varSize = 4)
{
    if (!processHandle) return false;

    uintptr_t sigAddr = Memory::FindSignature(processHandle, Game::modBaseAddr, Game::modBaseSize, sig);
    if (!sigAddr) return false;

    uintptr_t detourAddr = Memory::AllocateCodeCave(processHandle, sigAddr, detour.size() + 0x200);
    if (!detourAddr) return false;

    HookData data;
    data.hookAddr = sigAddr;
    data.detourAddr = detourAddr;
    data.valueAddr = detourAddr + 0x100;

    if (std::holds_alternative<int>(defaultValue))
    {
        int value = std::get<int>(defaultValue);
        if (!WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(data.valueAddr), &value, varSize, nullptr))
            return false;
    }
    else
    {
        float value = std::get<float>(defaultValue);
        if (!WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(data.valueAddr), &value, sizeof(float), nullptr))
            return false;
    }

    data.originalBytes.resize(hook.size());
    Memory::GetBytes(processHandle, sigAddr, data.originalBytes);

    uintptr_t hookOffset = Memory::CalculateJumpOffset(sigAddr, detourAddr);
    Memory::SetJump(hookOffset, hook);

    uintptr_t detourEnd = detourAddr + detour.size() - 5;
    uintptr_t hookEnd = sigAddr + hook.size();
    uintptr_t returnOffset = Memory::CalculateJumpOffset(detourEnd, hookEnd);
    Memory::SetJump(returnOffset, detour);

    if (!Memory::WriteBytes(processHandle, detourAddr, detour) ||
        !Memory::WriteBytes(processHandle, sigAddr, hook))
        return false;

    data.active = true;
    hooks[name] = data;
    return true;
}

bool eject(const std::string& name)
{
    auto it = hooks.find(name);
    if (it == hooks.end()) return false;

    HookData& data = it->second;
    if (!data.active) return false;

    if (!Memory::WriteBytes(processHandle, data.hookAddr, data.originalBytes))
        return false;

    if (data.detourAddr)
        VirtualFreeEx(processHandle, reinterpret_cast<LPVOID>(data.detourAddr), 0, MEM_RELEASE);

    data.active = false;
    hooks.erase(it);
    return true;
}

int main()
{
    SetConsoleTitleA("Minecraft Hook Manager");

    if (!Game::Initialize())
    {
        std::cout << "[*] Waiting for Minecraft to start...\n";
        while (!Game::Initialize())
            Sleep(1000);
    }

    std::cout << "[+] Connected to Minecraft\n";

    // 1.21.12101.0 (1.21.121)
    std::vector<int> reach_sig{ 0x74, -1, 0xF3, 0x0F, -1, -1, -1, -1, -1, -1, 0xEB, -1, 0xF3, 0x0F, -1, -1, -1, -1, -1, -1, 0x0F, 0x2F, -1, 0x76, -1, 0x41, 0xB5 };
    std::vector<int> reach_hook{ 0xE9, -1, -1, -1, -1, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    std::vector<int> reach_detour{ 0x90, 0xF3, 0x0F, 0x5D, 0x35, 0xF7, 0x00, 0x00, 0x00, 0xE9, -1, -1, -1, -1 };
    
    // 1.21.12101.0 (1.21.121)
    std::vector<int> fov_sig{ 0xF3, 0x0F, 0x10, 0x50, 0x18, 0xB9, 0x54, 0x01, 0x00, 0x00, 0xF3, 0x0F, 0x10, 0x48, 0x14, 0xF3, 0x0F, 0x10, 0x40, 0x10, 0x0F, 0x2F, 0xD1, 0x77, 0x07, 0x0F, 0x28, 0xC8, 0xF3, 0x0F, 0x5F, 0xCA, 0xF3, 0x0F };
    std::vector<int> fov_hook{ 0xE9, -1, -1, -1, -1 };
    std::vector<int> fov_detour{ 0xF3, 0x0F, 0x10, 0x15, 0xF8, 0x00, 0x00, 0x00, 0xE9, -1, -1, -1, -1 };

    if (inject("reach", reach_sig, reach_hook, reach_detour, 3.12f))
        std::cout << "[+] Reach hook injected\n";
    else
        std::cout << "[-] Failed to inject reach hook\n";

    if (inject("fov", fov_sig, fov_hook, fov_detour, 60.0f))
        std::cout << "[+] FOV hook injected\n";
    else
        std::cout << "[-] Failed to inject FOV hook\n";

    std::cout << "\nPress ENTER to eject hooks...\n";
    std::cin.get();

    if (eject("reach"))
        std::cout << "[+] Reach hook ejected\n";

    if (eject("fov"))
        std::cout << "[+] FOV hook ejected\n";

    return 0;

}
