---
title: "Shellcode Essentials"
date: 2025-01-09
categories: ["Assembly"]
tags: ["Exploit"]
---

# Shellcode Essentials: Finding Windows APIs Dynamically

## Background

Recently, I was analyzing one of the Expiro variants (around 2022) that was decrypting its code during runtime. It needed to resolve its APIs manually by parsing its Process Environment Block (PEB). While this technique is well documented, I decided to explore it further by writing my own shellcode.

## Understanding Shellcode

Shellcodes are position-independent code, meaning they can run without requiring the Windows loader to load their APIs. However, to perform meaningful operations, they need to call Windows APIs. Windows provides two crucial functions:

- `LoadLibrary`: Used to load modules in the current process
- `GetProcAddress`: Used to find the address of a function within a loaded module

If a shellcode can locate the address of these two functions, it gains the ability to:
1. Load any required modules using `LoadLibrary`
2. Find and call functions within those modules using `GetProcAddress`

## The Hunt for kernel32.dll

The `LoadLibrary` function resides within `kernel32.dll`, which is loaded into all Windows processes by default. Therefore, if we can:

1. Find the base address of `kernel32.dll` in memory
2. Parse its PE header
3. Locate the export table

We can ultimately find the address of the `LoadLibrary` function and bootstrap our shellcode's API resolution capabilities.

Let's start with parsing the PEB. The FS register can be used to get the TEB of any process, and using `[fs:0x30]` we get the PEB of the process.

![PEB Structure](/assets/img/shellcode/image.png)

Now the PEB further contains a field called LDR of type `_PEB_LDR_DATA` at offset `0xC`.

![LDR Structure](/assets/img/shellcode/image-1.png)

Digging further down the list and following the `_PEB_LDR_DATA` structure, we see that it contains fields like `InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`. These are the head of a linked list which contains the loaded modules by load order, in memory order, and initialization order respectively.

![Module List](/assets/img/shellcode/image-2.png)

Let's focus our attention on `InLoadOrderModuleList`. According to WinDbg, its type is `_LIST_ENTRY`, and Microsoft tells us that it's a head to a doubly-linked list, and each link (`*Flink` and `*Blink`) is a pointer to `LDR_DATA_TABLE_ENTRY` structure.

![LIST_ENTRY Structure](/assets/img/shellcode/image-3.png)

So if we follow the `InLoadOrderModuleList`, we should land on a `LDR_DATA_TABLE_ENTRY` structure. Let's attach our debugger to `notepad.exe` and follow the first `_LIST_ENTRY` structure.

![Debugging Notepad](/assets/img/shellcode/image-5.png)

![LDR_DATA_TABLE_ENTRY](/assets/img/shellcode/image-6.png)

The `_LDR_DATA_TABLE_ENTRY` has a field called `BaseDllName`, which is the name of our module, which is loaded first.

If we now follow the next `_LIST_ENTRY` again, we get `ntdll.dll`.

![ntdll.dll](/assets/img/shellcode/image-7.png)

Let's follow the `_LIST_ENTRY` for one last time, we get the `kernel32.dll`. Notice that we have another field called `BaseDll` that is the base address of the loaded DLL.

![kernel32.dll](/assets/img/shellcode/image-8.png)

This load order of module name, `ntdll.dll`, and `kernel32.dll` is going to be the same for Windows 10. We can use this information now to locate the base address of `kernel32.dll`.

```c
#include <Windows.h>
#include <stdio.h>

extern int get_kernel32_address();

int main()
{
	int kernel32_address, getproc_address;
	
	kernel32_address = get_kernel32_address();
	
	printf("kernel32 address is %x\r\n", kernel32_address);
}
```

```nasm
global _get_kernel32_address

section .text

_get_kernel32_address:
  xor eax, eax
  mov eax, [fs:0x30]   ; PEB
  
  mov eax, [eax + 0xC]  ; LDR offset
  
  mov eax, [eax + 0xC]  ; InLoadOrderModuleList
  
  mov eax, [eax] ; ntdll
  
  mov eax, [eax]  ; kernel32
  
  mov eax, [eax + 0x18] ; DLLBase
    
  ret
```

![Kernel32 Base Address](/assets/img/shellcode/image-9.png)

## Searching the LoadLibrary/GetProcAddress

Now that we have the base address of `kernel32.dll`, it's time to parse its header and exports in order to get the address of `LoadLibrary`/`GetProcAddress`. We can parse any one as an example. Let's parse `GetProcAddress`.

We can start off by jumping to the export directory.

![Export Directory](/assets/img/shellcode/image-10.png)

We can first jump to the `NumberOfNames` to find out the total number of named functions. After that, we can loop over all the name pointers to get a match with "GetProcAddress".

Here are a few things that we need to consider for the next stage:

1. The `AddressOfNames` has the array of name pointers. We need to iterate over this and compare with "GetProcAddress".
2. Once we find the index with a matching name, we can use that same index in `AddressOfNamesOrdinals` to get a value that can be used into the `AddressOfFunctions` as an index.
3. Now this value from `AddressOfNamesOrdinals` can directly act as an index into `AddressOfFunctions`. This index will give us the address of `GetProcAddress`.

![Export Table Diagram](/assets/img/shellcode/image-11.png)

*Fig: Here is a neat diagram illustrating the above (resources.infosecinstitute.com)*

Let's put it all together:

```c
#include <Windows.h>
#include <stdio.h>

extern int get_kernel32_address();
extern int fetch_getprocaddress(int);

int main()
{
	int kernel32_address, getproc_address;
	
	kernel32_address = get_kernel32_address();
	
	printf("kernel32 address is %x\r\n", kernel32_address);
	
	getproc_address = fetch_getprocaddress(kernel32_address);
	
	printf("GetProcAddress is at %x\r\n", getproc_address);
}
```

```nasm
global _get_kernel32_address
global _fetch_getprocaddress

section .text

_get_kernel32_address:
  xor eax, eax
  mov eax, [fs:0x30]   ; PEB
  
  mov eax, [eax + 0xC]  ; LDR offset
  
  mov eax, [eax + 0xC]  ; InLoadOrderModuleList
  
  mov eax, [eax] ; ntdll
  
  mov eax, [eax]  ; kernel32
  
  mov eax, [eax + 0x18] ; DLLBase
    
  ret
  
_fetch_getprocaddress:

  push 0x00007373   ; ss
  push 0x65726464   ; erdd
  push 0x41636F72   ; Acor
  push 0x50746547   ; PteG
  
  sub esp, 8      ; for local variables
  
  mov eax, [esp + 0x20] ; kernel32_address
  
  mov ebx, [eax + 0x3C] ; e_elfnew 
  
  add ebx, eax          ; Nt header 'PE'
  
  add ebx, 0x78           ; Export directory offset 
  
  mov ebx, [ebx]        ; Export directory rva 
  
  add ebx, eax          ; Export directory VA
  
  add ebx, 0x18         ; Number of names offset 
  
  mov ecx, [ebx]        ; Number of names 
  
  add ebx, 0x4          ; Address of Functions offset 
  
  mov [esp + 0x4], ebx  ; local var, offset of address of functions 
  
  add ebx, 0x4          ; Address of names offset 
  
  mov ebx, [ebx]         ; Address of names rva 
  
  add ebx, eax           ; Address of Names VA 
  
  mov edx, ecx           ; Number of names 
  
  xor ecx, ecx           ; using as index
  
  mov ecx, -1
  
  sub ebx, 4
  
  loop_start:
    
    inc ecx 
    
    cmp ecx, edx
    
    jz loop_end 
    
    
    add ebx, 4           ; dword holding address of function
        
    mov esi, eax         
    
    add esi, [ebx]       ; VA of function name string start
    
    mov edi, [esi]       
	
    cmp edi, [esp+0x8]   ; compare GetP
    
    jnz loop_start
    
    mov edi, [esi + 0x4]
    cmp edi, [esp + 0xC]  ; compare roca
    
    jnz loop_start
    
    mov edi, [esi + 0x8]
    cmp edi,  [esp + 0x10]  ; ddre
    
    jnz loop_start 
    
    movsx edi, word [esi + 0xC]
    movsx esi, word [esp + 0x14]
    
    cmp esi, edi 
    
    jnz loop_start 
     
  loop_end:
  
    cmp ecx, edx         
    jz end_program       ; terminating due to unmatched function name
  	
    mov ebx, [esp + 0x4] ; local var, offset of address of functions 
    
    add ebx, 0x8         ; offset of address of ordinals
    
    mov ebx, [ebx]       ; rva of address of ordinals 
    
    add ebx, eax         ; VA of address of ordinals 
    
    shl ecx, 1           
    
    add ebx, ecx         ; get the matched dword index     
    
    shr ecx, 1            ; restore ecx 
    
    movsx ebx, word [ebx]        ; get the index to address of functions 
    
    mov [esp], ebx        ; store the address of function index as local var 
    
    
    mov ebx, [esp + 0x4]   ; local var, offset of address of functions 
    
    mov ebx, [ebx]        ; rva of address of functions 
    
    add ebx, eax          ; VA of address of functions
    
    
    mov ecx, [esp]
    
    shl ecx, 2            
    
    add ebx, ecx           ; get the appropriate index of function 
    
    add eax , [ebx]        ; get the VA address of getprocaddress 
    
    add esp, 0x18
    
    ret 
	
	
   end_program:
	
     add esp, 0x18
     xor eax, eax 
     ret 
```

![GetProcAddress Resolution](/assets/img/shellcode/image-12.png)

Let's check if everything works as expected by fetching the address of `GetComputerName` API.

![GetComputerName API](/assets/img/shellcode/image-13.png)

Find all the reference code here: [GitHub Repository](https://github.com/rms523/shellcode-api-resolver.git)


## References

- [PEB_LDR_DATA structure (winternl.h)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
- [Windows Shellcoding x86 – Calling Functions in Kernel32.dll – Part 2](https://0xdarkvortex.dev/windows-shellcoding-x86-calling-functions-in-kernel32-dll-part-2/)
- [The Export Directory](https://www.infosecinstitute.com/resources/reverse-engineering/the-export-directory/)