#include "AntiDBG.h"
#include <iostream>
#define SHOW_DEBUG_MESSAGES

void DBG_MSG(WORD dbg_code, const char* message)
{
#ifdef SHOW_DEBUG_MESSAGES
    printf(XorString("[MSG-0x%X]: %s\n"), dbg_code, message);
    MessageBoxA(NULL, message, XorString("GAME OVER!"), 0);
#endif
}
#ifdef _WIN32
#include <windows.h>
void NTAPI TLSCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH || Reason == DLL_THREAD_ATTACH)
    {
        adbg_NtCloseCheck();
        AdvancedTimingCheck();
        adbg_CheckDebugRegisters();
        if (IsDebuggerPresent())
        {
            DBG_MSG(DBG_TLS_CALLBACK, XorString("Caught by TLS Callback!"));
            exit(DBG_TLS_CALLBACK);
        }
    }
}
#pragma comment(linker, XorString("/INCLUDE:_tls_used"))
#pragma const_seg(XorString(".CRT$XLB"))
EXTERN_C const PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma const_seg()
#endif
void AdvancedTimingCheck()
{
    LARGE_INTEGER start, end, frequency;
    QueryPerformanceFrequency(&frequency);

    QueryPerformanceCounter(&start);
    for (volatile int i = 0; i < 1000000; ++i);
    QueryPerformanceCounter(&end);

    LONGLONG duration = end.QuadPart - start.QuadPart;
    double timeTaken = (double)duration / frequency.QuadPart;

    if (timeTaken > 0.001)
    {
        DBG_MSG(DBG_ADVANCED_TIMING_CHECK, XorString("Advanced timing check detected debugger!"));
        exit(DBG_ADVANCED_TIMING_CHECK);
    }
}
void adbg_NtCloseCheck(void)
{
    BOOL found = FALSE;
    HANDLE hInvalid = (HANDLE)0xDEADBEEF;
    NTSTATUS status;

    typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);
    pNtClose NtClose = (pNtClose)GetProcAddress(GetModuleHandleA(XorString("ntdll.dll")), XorString("NtClose"));

    if (NtClose)
    {
        status = NtClose(hInvalid);
        if (status != STATUS_INVALID_HANDLE)
        {
            found = TRUE;
        }
    }

    if (found)
    {
        DBG_MSG(DBG_NTCLOSECHECK, XorString("Caught by NtCloseCheck!"));
        exit(DBG_NTCLOSECHECK);
    }
}
void adbg_CheckDebugRegisters(void)
{
    BOOL found = FALSE;
    CONTEXT ctx = { 0 };
    HANDLE hThread = GetCurrentThread();

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx))
    {
        if (ctx.Dr0 != 0x00 || ctx.Dr1 != 0x00 || ctx.Dr2 != 0x00 || ctx.Dr3 != 0x00 || ctx.Dr6 != 0x00 || ctx.Dr7 != 0x00)
        {
            found = TRUE;
        }
    }
    if (found)
    {
        DBG_MSG(DBG_CHECKDEBUGREGISTERS, XorString("Caught by CheckDebugRegisters!"));
        exit(DBG_CHECKDEBUGREGISTERS);
    }
}
void adbg_OutputDebugStringCheck(void)
{
    BOOL found = FALSE;
    SetLastError(0);
    OutputDebugStringA(XorString("Anti-Debugging Check"));
    if (GetLastError() != 0)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_STRCHECKS, XorString("Caught by OutputDebugStringCheck!"));
        exit(DBG_STRCHECKS);
    }
}
void adbg_ProcessDebugFlags(void)
{
    HANDLE hProcess = GetCurrentProcess();
    DWORD debugFlags = 0;
    ULONG returnLength = 0;
    typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
    HMODULE hNtdll = LoadLibraryA(XorString("ntdll.dll"));
    if (hNtdll == NULL)
    {
        return;
    }
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, XorString("NtQueryInformationProcess"));
    if (NtQueryInformationProcess == NULL)
    {
        return;
    }
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0x1F, &debugFlags, sizeof(debugFlags), &returnLength);
    if (status == 0x00000000 && debugFlags == 0)
    {
        DBG_MSG(DBG_PROCESSDEBUGFLAGS, XorString("Caught by ProcessDebugFlags check!"));
        exit(DBG_PROCESSDEBUGFLAGS);
    }
}
LONG WINAPI CustomUnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo)
{
    DBG_MSG(DBG_UNHANDLEDEXCEPTIONFILTER, XorString("Caught by Unhandled Exception Filter!"));
    exit(DBG_UNHANDLEDEXCEPTIONFILTER);
    return EXCEPTION_EXECUTE_HANDLER;
}
void adbg_SetUnhandledExceptionFilter(void)
{
    SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);
    __try
    {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}
void adbg_SelfModifyingCode(void)
{
    unsigned char code[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
    void* exec = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec == NULL)
    {
        DBG_MSG(DBG_SELFMODIFYINGCODE, XorString("VirtualAlloc failed!"));
        exit(DBG_SELFMODIFYINGCODE);
    }
    memcpy(exec, code, sizeof(code));
    typedef int(*func_t)();
    func_t func = (func_t)exec;
    int result = func();
    unsigned char new_code[] = 
    {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xC3
    };
    memcpy(exec, new_code, sizeof(new_code));
    result = func();
    VirtualFree(exec, 0, MEM_RELEASE);
    if (result == 1)
    {
        DBG_MSG(DBG_SELFMODIFYINGCODE, XorString("Caught by Self-Modifying Code check!"));
        exit(DBG_SELFMODIFYINGCODE);
    }
}
void xorEncryptDecrypt(char* data, size_t dataLen, const char* key, size_t keyLen)
{
    for (size_t i = 0; i < dataLen; ++i)
    {
        data[i] ^= key[i % keyLen];
    }
}
DWORD WINAPI HiddenThreadFunction(LPVOID lpParam)
{
    while (true)
    {
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        Sleep(10);

        QueryPerformanceCounter(&end);
        LONGLONG elapsed = end.QuadPart - start.QuadPart;
        if (elapsed > freq.QuadPart / 100)
        {
            DBG_MSG(DBG_NONE, XorString("Caught by Hidden Thread timing check!"));
            exit(DBG_NONE);
        }
        Sleep(500);
    }
    return 0;
}
const char key[] = "leksa";
void adbg_AntiRe(void)
{
    char codeBlock[] = 
    {
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
    xorEncryptDecrypt(codeBlock, sizeof(codeBlock), key, sizeof(key));
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
    xorEncryptDecrypt(codeBlock, sizeof(codeBlock), key, sizeof(key));
    void* exec = VirtualAlloc(NULL, sizeof(codeBlock), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec == NULL)
    {
        DBG_MSG(DBG_COMPLEXANTIREVERSING, XorString("VirtualAlloc failed!"));
        exit(DBG_COMPLEXANTIREVERSING);
    }
    memcpy(exec, codeBlock, sizeof(codeBlock));
    typedef int(*func_t)();
    func_t func = (func_t)exec;
    int result = func();
    VirtualFree(exec, 0, MEM_RELEASE);
    if (result != 1)
    {
        DBG_MSG(DBG_COMPLEXANTIREVERSING, XorString("Caught by Complex Anti-Reversing check!"));
        exit(DBG_COMPLEXANTIREVERSING);
    }
}
void adbg_BeingDebuggedPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_BeingDebuggedPEBx64();
#else
    _asm
    {
        xor eax, eax;
        mov eax, fs: [0x30] ;
        mov eax, [eax + 0x02];
        and eax, 0xFF;
        mov found, eax;
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_BEINGEBUGGEDPEB, XorString("Caught by BeingDebugged PEB check!"));
        exit(DBG_BEINGEBUGGEDPEB);
    }
}
void adbg_CheckRemoteDebuggerPresent(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &found);

    if (found)
    {
        DBG_MSG(DBG_CHECKREMOTEDEBUGGERPRESENT, XorString("Caught by CheckRemoteDebuggerPresent!"));
        exit(DBG_CHECKREMOTEDEBUGGERPRESENT);
    }
}
void adbg_CheckWindowName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowNameOlly = XorWideString(L"OllyDbg - [CPU]");
    const wchar_t* WindowNameImmunity = XorWideString(L"Immunity Debugger - [CPU]");
    hWindow = FindWindow(NULL, WindowNameOlly);
    if (hWindow)
    {
        found = TRUE;
    }
    hWindow = FindWindow(NULL, WindowNameImmunity);
    if (hWindow)
    {
        found = TRUE;
    }
    if (found)
    {
        DBG_MSG(DBG_FINDWINDOW, XorString("Caught by FindWindow (WindowName)!"));
        exit(DBG_FINDWINDOW);
    }
}
void adbg_ProcessFileName(void)
{
    const wchar_t *debuggersFilename[6] = {
       XorWideString(L"cheatengine-x86_64.exe"),
        XorWideString(L"ollydbg.exe"),
        XorWideString(L"ida.exe"),
        XorWideString(L"ida64.exe"),
        XorWideString(L"radare2.exe"),
       XorWideString(L"x64dbg.exe")
    };

    wchar_t* processName;
    PROCESSENTRY32W processInformation{ sizeof(PROCESSENTRY32W) };
    HANDLE processList;

    processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    processInformation = { sizeof(PROCESSENTRY32W) };
    if (!(Process32FirstW(processList, &processInformation)))
        printf(XorString("[Warning] It is impossible to check process list."));
    else
    {
        do
        {
            for (const wchar_t *debugger : debuggersFilename)
            {
                processName = processInformation.szExeFile;
                if (_wcsicmp(debugger, processName) == 0) {
                    DBG_MSG(DBG_PROCESSFILENAME, XorString("Caught by ProcessFileName!"));
                    exit(DBG_PROCESSFILENAME);
                }
            }
        } while (Process32NextW(processList, &processInformation));
    }
    CloseHandle(processList);
}
void adbg_CheckWindowClassName(void)
{
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    const wchar_t* WindowClassNameOlly = XorWideString(L"OLLYDBG");
    const wchar_t* WindowClassNameImmunity = XorWideString(L"ID");

    hWindow = FindWindow(WindowClassNameOlly, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    hWindow = FindWindow(WindowClassNameImmunity, NULL);
    if (hWindow)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_FINDWINDOW, XorString("Caught by FindWindow (ClassName)!"));
        exit(DBG_FINDWINDOW);
    }
}
void adbg_IsDebuggerPresent(void)
{
    BOOL found = FALSE;
    found = IsDebuggerPresent();

    if (found)
    {
        DBG_MSG(DBG_ISDEBUGGERPRESENT, XorString("Caught by IsDebuggerPresent!"));
        exit(DBG_ISDEBUGGERPRESENT);
    }
}
void adbg_NtGlobalFlagPEB(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    found = adbg_NtGlobalFlagPEBx64();
#else
    _asm
    {
        xor eax, eax;
        mov eax, fs: [0x30] ;
        mov eax, [eax + 0x68];
        and eax, 0x00000070;
        mov found, eax;
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_NTGLOBALFLAGPEB, XorString("Caught by NtGlobalFlag PEB check!"));
        exit(DBG_NTGLOBALFLAGPEB);
    }
}
void adbg_NtQueryInformationProcess(void)
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    PROCESS_BASIC_INFORMATION pProcBasicInfo = {0};
    ULONG returnLength = 0;
    HMODULE hNtdll = LoadLibraryW(XorWideString(L"ntdll.dll"));
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }
    _NtQueryInformationProcess  NtQueryInformationProcess = NULL;
    NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, XorString("NtQueryInformationProcess"));

    if (NtQueryInformationProcess == NULL)
    {
        return;
    }
    
    hProcess = GetCurrentProcess();

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pProcBasicInfo, sizeof(pProcBasicInfo), &returnLength);
    if (NT_SUCCESS(status)) {
        PPEB pPeb = pProcBasicInfo.PebBaseAddress;
        if (pPeb)
        {
            if (pPeb->BeingDebugged)
            {
                DBG_MSG(DBG_NTQUERYINFORMATIONPROCESS, XorString("Caught by NtQueryInformationProcess (ProcessDebugPort)!"));
                exit(DBG_NTQUERYINFORMATIONPROCESS);
            }
        }
    }
}
void adbg_NtSetInformationThread(void)
{
    THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;
    HMODULE hNtdll = LoadLibraryW(XorWideString(L"ntdll.dll"));
    if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
    {
        return;
    }
    _NtSetInformationThread NtSetInformationThread = NULL;
    NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, XorString("NtSetInformationThread"));

    if (NtSetInformationThread == NULL)
    {
        return;
    }
    NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}
void adbg_DebugActiveProcess(const char* cpid)
{
    BOOL found = FALSE;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    TCHAR szPath[MAX_PATH];
    DWORD exitCode = 0;

    CreateMutex(NULL, FALSE, XorWideString(L"antidbg"));
    if (GetLastError() != ERROR_SUCCESS)
    {
        if (DebugActiveProcess((DWORD)atoi(cpid)))
        {
            return;
        }
        else
        {
            exit(555);
        }
    }
    DWORD pid = GetCurrentProcessId();
    GetModuleFileName(NULL, szPath, MAX_PATH);

    char cmdline[MAX_PATH + 1 + sizeof(int)];
    snprintf(cmdline, sizeof(cmdline), XorString("%ws %d"), szPath, pid);
    BOOL success = CreateProcessA(
        NULL,
        cmdline,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCode == 555)
    {
        found = TRUE;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (found)
    {
        DBG_MSG(DBG_DEBUGACTIVEPROCESS, XorString("Caught by DebugActiveProcess!"));
        exit(DBG_DEBUGACTIVEPROCESS);
    }
}
void adbg_RDTSC(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
    uint64_t timeA = 0;
    uint64_t timeB = 0;
    TimeKeeper timeKeeper = { 0 };
    adbg_RDTSCx64(&timeKeeper);
    
    timeA = timeKeeper.timeUpperA;
    timeA = (timeA << 32) | timeKeeper.timeLowerA;

    timeB = timeKeeper.timeUpperB;
    timeB = (timeB << 32) | timeKeeper.timeLowerB;

    if (timeB - timeA > 0x100000)
    {
        found = TRUE;
    }

#else
    int timeUpperA = 0;
    int timeLowerA = 0;
    int timeUpperB = 0;
    int timeLowerB = 0;
    int timeA = 0;
    int timeB = 0;

    _asm
    {
        rdtsc;
        mov [timeUpperA], edx;
        mov [timeLowerA], eax;
        xor eax, eax;
        mov eax, 5;
        shr eax, 2;
        sub eax, ebx;
        cmp eax, ecx;

        rdtsc;
        mov [timeUpperB], edx;
        mov [timeLowerB], eax;
    }

    timeA = timeUpperA;
    timeA = (timeA << 32) | timeLowerA;

    timeB = timeUpperB;
    timeB = (timeB << 32) | timeLowerB;
    if (timeB - timeA > 0x10000)
    {
        found = TRUE;
    }

#endif

    if (found)
    {
        DBG_MSG(DBG_RDTSC, XorString("Caught by RDTSC!"));
        exit(DBG_RDTSC);
    }
}
void adbg_QueryPerformanceCounter(void)
{
    BOOL found = FALSE;
    LARGE_INTEGER t1;
    LARGE_INTEGER t2;

    QueryPerformanceCounter(&t1);

#ifdef _WIN64
    adbg_QueryPerformanceCounterx64();
#else
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif

    QueryPerformanceCounter(&t2);
    if ((t2.QuadPart - t1.QuadPart) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_QUERYPERFORMANCECOUNTER, XorString("Caught by QueryPerformanceCounter!"));
        exit(DBG_QUERYPERFORMANCECOUNTER);
    }
}
void adbg_GetTickCount(void)
{
    BOOL found = FALSE;
    DWORD t1;
    DWORD t2;

    t1 = GetTickCount();

#ifdef _WIN64
    adbg_GetTickCountx64();
#else
    _asm
    {
        xor eax, eax;
        push eax;
        push ecx;
        pop eax;
        pop ecx;
        sub ecx, eax;
        shl ecx, 4;
    }
#endif
    t2 = GetTickCount();
    if ((t2 - t1) > 30)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_GETTICKCOUNT, XorString("Caught by GetTickCount!"));
        exit(DBG_GETTICKCOUNT);
    }
}
void adbg_HardwareDebugRegisters(void)
{
    BOOL found = FALSE;
    CONTEXT ctx = { 0 };
    HANDLE hThread = GetCurrentThread();

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx))
    {
        if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
        {
            found = TRUE;
        }
    }

    if (found)
    {
        DBG_MSG(DBG_HARDWAREDEBUGREGISTERS, XorString("Caught by a Hardware Debug Register Check!"));
        exit(DBG_HARDWAREDEBUGREGISTERS);
    }
}
void adbg_MovSS(void)
{
    BOOL found = FALSE;

#ifdef _WIN64
#else
    _asm
    {
        push ss;
        pop ss;
        pushfd;
        test byte ptr[esp + 1], 1;
        jne fnd;
        jmp end;
    fnd:
        mov found, 1;
    end:
        nop;
    }
#endif

    if (found)
    {
        DBG_MSG(DBG_MOVSS, XorString("Caught by a MOV SS Single Step Check!"));
        exit(DBG_MOVSS);
    }
}
void adbg_CloseHandleException(void)
{
    HANDLE hInvalid = (HANDLE)0xBEEF;
    DWORD found = FALSE;

    __try
    {
        CloseHandle(hInvalid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = TRUE;
    }

    if (found)
    {
        DBG_MSG(DBG_CLOSEHANDLEEXCEPTION, XorString("Caught by an CloseHandle exception!"));
        exit(DBG_CLOSEHANDLEEXCEPTION);
    }
}
void adbg_SingleStepException(void)
{
    DWORD found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_SingleStepExceptionx64();
#else
        _asm
        {
            pushfd;
            or byte ptr[esp + 1], 1;
            popfd;
        }
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_SINGLESTEPEXCEPTION, XorString("Caught by a Single Step Exception!"));
        exit(DBG_SINGLESTEPEXCEPTION);
    }
}
void adbg_Int3(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int3x64();
#else
        _asm
        {
            int 3;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_INT3CC, XorString("Caught by a rogue INT 3!"));
        exit(DBG_INT3CC);
    }
}
void adbg_PrefixHop(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        found = FALSE;
#else
        _asm
        {
            __emit 0xF3;
            __emit 0x64;
            __emit 0xCC;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_PREFIXHOP, XorString("Caught by a Prefix Hop!"));
        exit(DBG_PREFIXHOP);
    }
}
void adbg_Int2D(void)
{
    BOOL found = TRUE;

    __try
    {
#ifdef _WIN64
        adbg_Int2Dx64();
#else
        _asm
        {
            int 0x2D;
            nop;
        }
#endif
    }

    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE;
    }

    if (found)
    {
        DBG_MSG(DBG_NONE, XorString("Caught by a rogue INT 2D!"));
        exit(DBG_NONE);
    }
}
void adbg_CrashOllyDbg(void)
{
    __try {
        OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { ; }
}