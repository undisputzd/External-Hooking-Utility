# Minecraft Hook Manager

An external memory hooking tool for Minecraft Bedrock Edition. This tool provides a clean, organized system for injecting and managing multiple external hooks with minimal code.

## Features

- **External Memory Manipulation**: No DLL injection required - operates entirely from outside the game process
- **Simple Hook Management**: Inject and eject hooks with single function calls
- **Multi-Hook Support**: Manage multiple hooks simultaneously with named identifiers
- **Automatic Memory Management**: Handles code cave allocation and memory cleanup automatically
- **Type-Safe Values**: Support for both integer and floating-point hook values

## How It Works

The external hooking system operates by:
1. **Process Attachment**: Opens a handle to the Minecraft process
2. **Signature Scanning**: Locates target code in memory using byte patterns
3. **Remote Code Cave Allocation**: Allocates executable memory in the target process
4. **Jump Redirection**: Redirects execution flow from original code to custom detour
5. **Value Injection**: Writes custom values that the detour references
6. **Clean Restoration**: Restores original bytes and frees allocated memory on ejection

All operations are performed externally using Windows API - no code is injected into the game process itself.

## Usage
```cpp
// Define your hook patterns
std::vector<int> signature = { 0x74, 0x0B, 0xF3, ... };
std::vector<int> hook = { 0xE9, -1, -1, -1, -1, ... };
std::vector<int> detour = { 0xF3, 0x44, 0x0F, ... };

// Inject an external hook
inject("reach", signature, hook, detour, 3.12f);

// Eject the hook when done
eject("reach");
```

## Disclaimer

This tool is for educational purposes only. Use at your own risk.

Join my discord server below 😄: https://discord.gg/sCWYtYDjjr
