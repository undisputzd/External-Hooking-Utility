# Minecraft Hook Manager

An external memory hooking tool for Minecraft Bedrock Edition. Clean system for managing multiple external hooks with minimal code.

## Features

- **External Memory Manipulation**: No DLL injection - operates entirely outside the game process
- **Simple Hook Management**: Inject and eject hooks with single function calls
- **Multi-Hook Support**: Manage multiple hooks simultaneously with named identifiers
- **Automatic Memory Management**: Handles code cave allocation and cleanup automatically
- **Type-Safe Values**: Support for both integer and floating-point hook values
- **Pointer Resolution**: Read and resolve pointer addresses from injected hooks

## How It Works

1. **Process Attachment**: Opens a handle to the Minecraft process
2. **Signature Scanning**: Locates target code using byte patterns
3. **Remote Code Cave Allocation**: Allocates executable memory in target process
4. **Jump Redirection**: Redirects execution from original code to custom detour
5. **Value Injection**: Writes custom values that the detour references
6. **Clean Restoration**: Restores original bytes and frees allocated memory

## Usage
```cpp
std::vector<int> signature = { 0x74, 0x0B, 0xF3, ... };
std::vector<int> hook = { 0xE9, -1, -1, -1, -1, ... };
std::vector<int> detour = { 0xF3, 0x44, 0x0F, ... };

inject("reach", signature, hook, detour, 3.12f);

write("reach", 4.5f);

uintptr_t resolvedAddr = resolvePointer("reach");

eject("reach");
```

## API Reference

### `inject(name, signature, hook, detour, defaultValue, varSize)`
Injects an external hook into the target process.

### `eject(name)`
Removes the hook and restores original bytes.

### `write(name, value)`
Updates the value at the hook's allocated memory address.

### `read(name, value)`
Reads the value at the hook's allocated memory address.

### `resolvePointer(name)`
Reads and returns the resolved pointer address from the hook's memory.

## Disclaimer

This tool is for educational purposes only. Use at your own risk.

Join my discord server: https://discord.gg/sCWYtYDjjr
