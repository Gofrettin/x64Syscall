## x64Syscall
Execute direct system-calls for kernel functions on Windows in x64.

## Requirements
- C++20 or above, Legacy C Language Standard.

## Implementation (MSVC)
Implementation is extremely easy. Please keep in mind before hand, that this current test was conducted on MSCV on Visual Studio 2019.
- 1. Create a new file in your project named 'syscall.asm' or drag and drop the one available here.
- 2. Add the the x64Syscall.h header file from here to your project.
- 3. Select your project > Build Dependencies > Build Customizations > Check 'masm(.targets, .props) > Ok
 
## Purpose
The purpose of this library is to call system-calls (kernel-level) directly to prevent user-mode hooks and monitoring. This library has a small level of compile-time 'obfuscation' that produces, what looks like, a bunch of gibberish.

## Usage
```cpp
#include <Windows.h>
#include "x64Syscall.h"

int main()
{
    LoadLibraryA("win32u.dll");
    LoadLibraryA("ntdll.dll");
    LoadLibraryA("user32.dll");

    int testVar = 100;
    int readData{};

    while (true)
    {
        if (x64Syscall::Call<NTSTATUS>(HASH("win32u.dll"), HASH("NtUserGetAsyncKeyState"), VK_DELETE) & 1)
            break;

        if (x64Syscall::Call<NTSTATUS>(HASH("win32u.dll"), HASH("NtUserGetAsyncKeyState"), VK_INSERT) & 1)
        {
            printf("INS\n");
        }

        Sleep(1);
    }

    std::cin.get();
    return EXIT_SUCCESS;
}
```
