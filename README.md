## x64Syscall
Execute direct system-calls for kernel functions on Windows in x64.

## Requirements
- C++20 or above, Legacy C Language Standard.

## Implementation (MSVC)
Implementation is extremely easy. Please keep in mind before hand, that this current test was conducted on MSVC on Visual Studio 2019.
- Create a new file in your project named 'syscall.asm' or drag and drop the one available here.
- Add the the x64Syscall.h header file from here to your project.
- Select your project > Build Dependencies > Build Customizations > Check 'masm(.targets, .props) > Ok
 
## Purpose
The purpose of this library is to execute system-calls (kernel-level) directly to prevent user-mode hooks and monitoring. This library has a small level of compile-time 'obfuscation' that produces, what looks like, a bunch of gibberish.

![This is an image](https://i.imgur.com/RvkIrKj.png)
As you can deduce from the provided diagram, the defender cannot monitor our system-call which bypasses all user-mode callbacks before the kernel-function is called.

## Information
- What is a system-call: A system call is a technical instruction in the Windows operating system that allows a temporary transition from user mode to kernel mode. This is necessary, for example, when a user-mode application such as Notepad wants to save a document. Each system call has a specific syscall ID, which can vary from one version of Windows to another. Direct system calls are a technique for attackers (red team) to execute code in the context of Windows APIs via system calls without the targeted application (malware) obtaining Windows APIs from Kernel32.dll or native APIs from Ntdll.dll. The assembly instructions required to switch from user mode to kernel mode are built directly into the malware.

## Usage
```cpp
#include <Windows.h>
#include "x64Syscall.h"

int main()
{
    LoadLibraryA("win32u.dll");

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

## Output
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  while ( 1 )
  {
    if ( (sub_140001970(0xB9CAA63E0729A11Eui64, 0xDB8E60AEE6BE24C9ui64, envp) & 1) != 0 )
      sub_140001010("INS\n");
    Sleep(1u);
  }
}
```

```cpp
__int64 __fastcall sub_140001970(__int64 a1, __int64 a2)
{
  __int64 v3; // rax
  __int64 v4; // r10
  int v5; // eax
  __int64 v6; // rax
  _DWORD *v7; // rsi
  unsigned int v8; // eax
  __int64 v9; // rdi
  __int64 v10; // rbx
  unsigned int *v11; // r11
  __int64 v12; // rbp
  char *v13; // rdx
  __int64 v14; // rax
  __int64 v15; // r8
  __int64 v16; // r9
  __int64 v17; // rax

  v3 = sub_140001230();
  v4 = v3;
  if ( v3 )
  {
    v6 = v3 + *(v3 + 60);
    if ( v6 )
    {
      v7 = (v4 + *(v6 + 136));
      if ( !v7 )
      {
        v5 = 0;
        return sub_140001E00(45, 0, 0, 0, v5);
      }
      v8 = v7[6];
      v9 = 0i64;
      if ( !v8 )
        goto LABEL_26;
      v10 = 0i64;
      v11 = (v4 + v7[8]);
      v12 = v8;
      while ( 1 )
      {
        v13 = (v4 + *v11);
        if ( v13 )
        {
          if ( *v13 == 78 )
          {
            if ( v13[1] == 116 )
              goto LABEL_14;
          }
          else if ( *v13 == 90 && v13[1] == 119 )
          {
LABEL_14:
            LODWORD(v14) = 0;
            do
              v14 = (v14 + 1);
            while ( v13[v14] );
            if ( v14 )
            {
              v15 = 0i64;
              v16 = v14;
              do
              {
                v17 = *v13++;
                v15 = 2166136261u * ((16777619 * v17) ^ v15);
                --v16;
              }
              while ( v16 );
            }
            else
            {
              v15 = 0i64;
            }
            if ( v15 == a2 )
              v9 = v4 + *(v4 + v7[7] + 4i64 * *(v10 + v7[9] + v4));
          }
        }
        ++v11;
        v10 += 2i64;
        if ( !--v12 )
        {
          if ( v9 )
          {
            v5 = *(v9 + 4);
            return sub_140001E00(45, 0, 0, 0, v5);
          }
LABEL_26:
          v5 = 0;
          return sub_140001E00(45, 0, 0, 0, v5);
        }
      }
    }
  }
  v5 = 0;
  return sub_140001E00(45, 0, 0, 0, v5);
}
```
