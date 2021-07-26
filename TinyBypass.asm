.486
.model flat, stdcall
option casemap :none
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\ntdll.lib

include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\windows.inc
include \masm32\include\msvcrt.inc
include \masm32\include\masm32.inc
include \masm32\macros\macros.asm
include \masm32\include\ntdll.inc

.data

kernel32name db "kernel32.dll",0
kernel32 dd 00000000
ntdllname db "ntdll.dll",0
ntdll dd 00000000

ntopenfilename db "NtOpenFile",0
ldrloaddllname db "LdrLoadDll",0
p32fAName db "Process32First",0
p32nAName db "Process32Next",0

Process32First dd 00000000
Process32Next dd 00000000
ntopenfile dd 00000000
ldrloaddll dd 00000000

processname db "csgo.exe",0    ; process name
handle dd 00000000
ps db 128 dup(?)
pid dd 00000000

.code

getproc proc var1:DWORD

fn GetProcAddress,ebx,var1
test eax,eax
je FAILED
ret 4

getproc endp


start:


    fn GetModuleHandleA,offset ntdllname
    test eax,eax
    je FAILED
    mov [ntdll],eax
    mov ebx,eax

    INVOKE getproc,offset ntopenfilename
    mov [ntopenfile],eax

    INVOKE getproc,offset ldrloaddllname
    mov [ldrloaddll],eax

    fn GetModuleHandleA,offset kernel32name
    test eax,eax
    je FAILED
    mov [kernel32],eax
    mov ebx,eax
    
    INVOKE getproc,offset p32fAName
    mov [Process32First],eax

    INVOKE getproc,offset p32nAName
    mov [Process32Next],eax


    fn CreateToolhelp32Snapshot,2,0
    cmp eax,0FFFFFFFFh ; is invalid handle
    je EXIT
    
    mov [handle],eax
    mov eax,296
    mov ebx,offset ps
    mov [ebx],eax

    push offset ps
    push handle
    call Process32First    

    test al,al
    je EXIT

CMPNAME:
    lea eax,[ebx+024h] ; mov eax,ps.szExeFile

    fn crt_strcmp,eax,offset processname

    test al,al
    je FOUND

    push offset ps
    push handle
    call Process32Next
    test al,al
    je FAILED
    jmp CMPNAME

FOUND:
    fn CloseHandle,handle

    mov eax,[ebx+08h] ; get processid from PROCESSENTRY32 struct
    fn OpenProcess,2035711,0,eax
    test eax,eax
    je FAILED
    
    mov [handle],eax

    fn WriteProcessMemory,handle,ntopenfile,ntopenfile,5,0 ;bypass jmp hook(5bytes)
    test al,al
    je FAILED
    
    fn WriteProcessMemory,handle,ldrloaddll,ldrloaddll,5,0 ;^
    test al,al
    je FAILED

    fn MessageBox,0,"Done",0,MB_OK
    jmp EXIT

FAILED:
    fn MessageBox,0,"Failed to bypass",0,MB_OK
EXIT:
    fn ExitProcess,0

end start
