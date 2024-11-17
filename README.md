Win32k.sys for Windows is similar to Java for the internet.

This project consists of two parts:

UAF (Use-After-Free) detector in Win32k
Win32k.sys fuzzer
I’ve just published the first part.

Win32k.sys for Windows is akin to Java for the internet.

In recent times, 0-day kernel vulnerabilities have become more valuable due to the limitations imposed by sandboxes. Every RCE exploit now requires an additional phase to bypass these restrictions in order to achieve full system access.

Many local privilege escalation vulnerabilities are based on flaws in Win32k, particularly how it handles or uses objects. In most cases, Win32k uses freed memory, leading to use-after-free vulnerabilities.

Win32k uses HMAllocObject to allocate memory, and the function utilizes different memory management subsystems based on the object type, either from the heap or from the pool, for object management. These memory management functions include:
```
int __stdcall HMAllocObject(int a1, PVOID Object, char a3, ULONG Size)
{
	....
	....

  if ( v5 & 0x10 && Object )
  {
    v7 = DesktopAlloc((int)Object, Size, ((unsigned __int8)a3 << 16) | 5);
    if ( !v7 )
    {
LABEL_28:
      UserSetLastError(8);
      return 0;
    }
    LockObjectAssignment(v7 + 12, Object);
    *(_DWORD *)(v7 + 16) = v7;
  }
  else
  {
    if ( v5 & 0x40 )
    {
      v8 = SharedAlloc(Size);
    }
    else
    {
      v9 = !Object && v5 & 0x20;
      if ( !(v5 & 8) || v9 )
        v8 = Win32AllocPoolWithTagZInit(Size, dword_BF9F191C[v4]);
      else
        v8 = Win32AllocPoolWithQuotaTagZInit(Size, dword_BF9F191C[v4]);
    }
    v7 = v8;
	....
	....
	....
	....
  }
  ```
DesktopAlloc (function uses heap)
SharedAlloc (function uses heap)
in32AllocPoolWithQuotaTagZInit, Win32AllocPoolWithTagZInit (function uses pool)
For example, a Menu object uses DesktopAlloc, while an Accelerator object uses Pool.

For objects that use heap memory, when the object's life ends, the OS calls RtlFreeHeap to free the used memory. However, after RtlFreeHeap returns, the freed memory still contains the old/valid contents. If another part of win32k.sys uses the freed memory, nothing will happen because it uses memory with old contents (no BSOD occurs), and the bug will be missed.

Until now, researchers have typically discovered these types of bugs through reverse engineering. They must allocate an object of the same size to trigger a crash. But how can one know when the OS will use the freed memory?

In user-mode code, we can use GFlags to enable PageHeap system-wide. This doesn't affect the heap implementation in the kernel. There is also a "special pool" that can be enabled with the verifier, but it doesn't help us with heap-based objects or memory.
```
gflags.exe /i iexplore.exe +hpa +ust to to enable the page Heap (HPA)
```
So, my idea is to patch RtlFreeHeap and fill the freed memory with invalid content, such as 0c0c0c0c.

With the help of the RtlSizeHeap function (thanks to @ponez for discovering this function), we can detect when win32k uses freed heap memory. We can also automatically determine how the OS uses freed memory—whether it reads, writes, or executes from the freed memory.
```
__declspec(naked) my_function_detour_RtlFreeHeap()
{
	//PVOID  func=RtlSizeHeap;;
	__asm
	{		
		// exec missing instructions
		mov     edi,edi
		push    ebp
		mov     ebp,esp
		push    ebx
		mov     ebx,dword ptr [ebp+10h]
		int 3;
		/*
		BOOLEAN	RtlFreeHeap
		( 
		IN PVOID  HeapHandle,
		IN ULONG  Flags,
		IN PVOID  HeapBase
		); 
		mov     ebx,dword ptr [ebp+10h] get HeapBase  
		*/
		PUSHAD
		PUSH dword ptr [ebp+10h]
		PUSH dword ptr [ebp+0Ch]
		PUSH dword ptr [ebp+08h]
		call RtlSizeHeap;
		sub  ecx,ecx;
		mov ecx, eax; // size from RtlSizeHeap
		mov eax, 0x0c
		mov edi, ebx; // address of heap chunk
		rep stos byte ptr es:[edi]
		POPAD
}
```
I tested this detector with some old UAF vulnerabilities in Win32k and a driver to detect UAF in win32k.sys. Maybe there is another way to do this, though! (I don’t know, maybe with GFlags, we can enable PageHeap for the kernel).

