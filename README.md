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
