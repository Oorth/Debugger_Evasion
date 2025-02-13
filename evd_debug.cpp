//cl /EHsc .\evd_debug.cpp debug_check.obj /link user32.lib Advapi32.lib /OUT:evd_debug.exe
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
#include <thread>
#include <winternl.h>       // header for PEB
typedef struct _PEB* PPEB;  // Define PPEB type

extern "C" BOOL IsDebuggerPresentASM();
///////////////////////////////////////////////////////////////////////////////
#define Use_IsDebuggerPresentASM 1                  
#define Use_DetectHardwareBreakpoints 1             
#define Use_CheckHeapPatterns 1                     

#define Use_CrashIfDebugged 1
///////////////////////////////////////////////////////////////////////////////

volatile bool exitProgram = false;

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
void CrashIfDebugged()
{
    if (IsDebuggerPresent())
    {
        // Write to NULL to cause an access violation and crash
        *(volatile int*)0 = 0;
    }
}
///////////////////////////////////////////////////////////////////////

void DebuggingThread()
{
    while(!exitProgram)
    {
        #if Use_DetectHardwareBreakpoints
            if (DetectHardwareBreakpoints())
            {
                std::cout << "Debugger detected! from DetectHardwareBreakpoints" << std::endl;
                #if Use_CrashIfDebugged
                    // Removed unconditional call to CrashIfDebugged
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
        
        CrashIfDebugged();

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
