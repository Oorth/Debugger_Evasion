//cl /EHsc .\evd_debug.cpp debug_check.obj /link user32.lib Advapi32.lib /OUT:evd_debug.exe

#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
#include <thread>
#include <winternl.h>       // header for PEB
typedef struct _PEB* PPEB;  // Define PPEB type

///////////////////////////////////////////////////////////////////////////////
extern "C" BOOL IsDebuggerPresentASM();
void CrashIfDebugged();
///////////////////////////////////////////////////////////////////////////////
#define Use_IsDebuggerPresentASM 1                  
#define Use_DetectHardwareBreakpoints 1             
#define Use_CheckHeapPatterns 1                     

#define Use_CrashIfDebugged 1
///////////////////////////////////////////////////////////////////////////////
volatile bool exitProgram = false;

///////////////////////////////////////////////////////////////////////////////

bool CheckHeapPatterns()
{
    DWORD numHeaps = GetProcessHeaps(0, NULL);
    HANDLE* heaps = new (std::nothrow) HANDLE[numHeaps];
    if (!heaps)
    {
        std::cerr << "Failed to allocate memory for heaps." << std::endl;
        return false;
    }
    GetProcessHeaps(numHeaps, heaps);

    for(DWORD i = 0; i < numHeaps; ++i)
    {
        PROCESS_HEAP_ENTRY HeapEntry = { 0 };
        while (HeapWalk(heaps[i], &HeapEntry))
        {
            if (HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
            {
                PBYTE pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;                                 // Memory after allocation
                if (*(PDWORD)pOverlapped == 0xABABABAB)
                {
                    std::cout << "Heap pattern detected (0xABABABAB)! at heap #" << i << std::endl;
                    return true;
                }
                else if (*(PDWORD)pOverlapped == 0xFEEEFEEE)
                {
                    std::cout << "Heap pattern detected (0xFEEEFEEE)! at heap #" << i << std::endl;
                    return true;
                }
            }
        }
    }
    if (heaps)
    {
        delete[] heaps;
    }

    return false;
}

bool DetectHardwareBreakpoints()
{
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
    {
        std::cerr << "Failed to get thread context." << std::endl;
        return false;
    }

    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    return false;
}

/////////////////////////////////////////////////////////////////////

void DebuggingThread()
{
    while(!exitProgram)
    {
        #if Use_DetectHardwareBreakpoints
            if (DetectHardwareBreakpoints())
            {
                std::cout << "Debugger detected! from DetectHardwareBreakpoints" << std::endl;
                #if Use_CrashIfDebugged
                    CrashIfDebugged();
                #endif
                exitProgram = true;
            }
        #endif

        #if Use_IsDebuggerPresentASM
            if (IsDebuggerPresentASM())
            {
                std::cout << "Debugger detected! from Use_IsDebuggerPresentASM" << std::endl;
                #if Use_CrashIfDebugged
                    CrashIfDebugged();
                #endif
                exitProgram = true;
            }
        #endif

        #if Use_CheckHeapPatterns
            if(CheckHeapPatterns())
            {
                std::cout << "Debugger detected! from CheckHeapPatterns" << std::endl;
                #if Use_CrashIfDebugged
                    CrashIfDebugged();
                #endif
                exitProgram = true;
            }
        #endif

        Sleep(1000);
    }
}

int main()
{

    std::thread debugThread(DebuggingThread);
    int i=0;
    while (!exitProgram)
    {
        std::cout << "Main Thread: " << i++ << std::endl;
        Sleep(1000);
    }
    
    debugThread.join();
    return 0;
}

void CrashIfDebugged()
{
    DWORD oldProtect;

    void* pMain = (void*)&main;

    // Modify memory protections to allow writing
    VirtualProtect(pMain, 16, PAGE_EXECUTE_READWRITE, &oldProtect);

    // Overwrite main() with garbage (0x90 NOP sled + 0xCC INT 3 to crash)
    memset(pMain, 0x90, 16);  // Fill with NOPs (no operation)
    *((BYTE*)pMain + 15) = 0xCC;  // INT 3 (debugger trap)

    VirtualProtect(pMain, 16, oldProtect, &oldProtect);
    std::cout << "Main changed" << std::endl;

    //===================================================================================

    BYTE patchBytes[] ={ 
        0xCC, 0x90, 0x90, 0xCC,          // INT 3, NOP, NOP, INT 3
        0x9C,                            // PUSHFD (push EFLAGS register)
        0xB8, 0x01, 0x00, 0x00, 0x00,    // MOV EAX, 1
        0xB8, 0x02, 0x00, 0x00, 0x00,    // MOV EAX, 2
        0x8B, 0xD0,                      // MOV EDX, EAX
        0x83, 0xC2, 0x01,                // ADD EDX, 1
        0x83, 0xEA, 0x01,                // SUB EDX, 1
        0x9D,                            // POPFQ (pop RFLAGS register)
        0x48, 0x89, 0xE5,                // MOV RBP, RSP (set up stack frame)
        0x48, 0x8B, 0x45, 0xF8,          // MOV RAX, [RBP-8] (load RDI)
        0x48, 0x8B, 0x4D, 0xF0,          // MOV RCX, [RBP-16] (load RSI)
        0x48, 0x01, 0xC8,                // ADD RAX, RCX (add RDI and RSI)
        0x48, 0x89, 0x45, 0xF8,          // MOV [RBP-8], RAX (store result)
        0x48, 0x8B, 0x45, 0xF8,          // MOV RAX, [RBP-8] (load result)
        0x48, 0x83, 0xC4, 0x10,          // ADD RSP, 16 (deallocate stack space)
        0x5D,                            // POP RBP (restore RBP)
        0xCC,                            // INT 3 (breakpoint)
        0x90,                            // NOP (no operation)
        0xEB, 0xFE,                      // JMP short -2 (infinite loop)
        0xC3,                             // RET (return from function)
        0x48, 0x83, 0xEC, 0x10,          // SUB RSP, 16 (allocate stack space)
        0x48, 0x89, 0x7D, 0xF8,          // MOV [RBP-8], RDI (save RDI)
        0x48, 0x89, 0x75, 0xF0,          // MOV [RBP-16], RSI (save RSI)
        0x48, 0x8B, 0x45, 0xF8,          // MOV RAX, [RBP-8] (load RDI)
        0x48, 0x8B, 0x4D, 0xF0,          // MOV RCX, [RBP-16] (load RSI)
        0x48, 0x01, 0xC8,                // ADD RAX, RCX (add RDI and RSI)
        0x48, 0x89, 0x45, 0xF8,          // MOV [RBP-8], RAX (store result)
        0x48, 0x8B, 0x45, 0xF8,          // MOV RAX, [RBP-8] (load result)
        0x48, 0x83, 0xC4, 0x10,          // ADD RSP, 16 (deallocate stack space)
        0x5D,                            // POP RBP (restore RBP)
        0xCC,                            // INT 3 (breakpoint)
        0x90,                            // NOP (no operation)
        0xEB, 0xFE,                      // JMP short -2 (infinite loop)
        0xC3,                            // RET (return from function)
        0x9C,                            // PUSHFD (push EFLAGS register)
        0xB8, 0x03, 0x00, 0x00, 0x00,    // MOV EAX, 3
        0xBB, 0x04, 0x00, 0x00, 0x00,    // MOV EBX, 4
        0x01, 0xD8,                      // ADD EAX, EBX
        0x83, 0xC0, 0x01,                // ADD EAX, 1
        0x83, 0xE8, 0x01,                // SUB EAX, 1
        0x9D,                            // POPFD (pop EFLAGS register)
        0xEB, 0xFE,                      // JMP short -2 (infinite loop)
        0xC3                             // RET (return from function)
    };
    
    VirtualProtect((LPVOID)CrashIfDebugged, sizeof(patchBytes), PAGE_EXECUTE_READWRITE, &oldProtect);


    memcpy((LPVOID)CrashIfDebugged, patchBytes, sizeof(patchBytes));
    VirtualProtect((LPVOID)CrashIfDebugged, sizeof(patchBytes), oldProtect, &oldProtect);
    std::cout << "function changed" << std::endl;


}