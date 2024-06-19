#define _CRT_SECURE_NO_WARNINGS
#include "AntiDBG.h"

#include <windows.h>
#include <iostream>

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
        std::cerr << "Failed to get module handle" << std::endl;
        return;
    }
    BYTE* pBaseAddr = (BYTE*)hModule;
    DWORD oldProtect;
    // Change the memory protection to be writable
    if (!VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &oldProtect)) 
    {
        std::cerr << "Failed to change memory protection" << std::endl;
        return;
    }
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBaseAddr;
    // Check the DOS header signature
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
    {
        std::cerr << "Invalid DOS header signature" << std::endl;
        return;
    }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pBaseAddr + dosHeader->e_lfanew);
    // Check the NT header signature
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) 
    {
        std::cerr << "Invalid NT header signature" << std::endl;
        return;
    }
    // Obfuscate the PE header by XORing specific fields
    ntHeaders->FileHeader.NumberOfSections ^= 0xDEAD;
    ntHeaders->OptionalHeader.CheckSum ^= 0xBEEF;
    // Restore the original memory protection
    if (!VirtualProtect(pBaseAddr, 4096, oldProtect, &oldProtect)) 
    {
        std::cerr << "Failed to restore memory protection" << std::endl;
        return;
    }

    std::cout << "PE header obfuscated successfully." << std::endl;
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
    std::string Dimen = ("LksAnti-");
    std::string Wyp = ("DBG-");
    // Generate a random string of 5 characters
    for (unsigned int i = 0; i < 5; ++i)
    {
        Str += genRandomn();
    }
    // Create the new filename
    std::string rename = Dimen + Wyp + Str + (".exe");
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
        // List of process names to terminate
        "KsDumperClient.exe", "KsDumper.exe", "HTTPDebuggerUI.exe", "HTTPDebuggerSvc.exe",
        "ProcessHacker.exe", "idaq.exe", "idaq64.exe", "Wireshark.exe", "Fiddler.exe",
        "FiddlerEverywhere.exe", "Xenos64.exe", "Xenos.exe", "Xenos32.exe", "de4dot.exe",
        "Cheat Engine.exe", "HTTP Debugger Windows Service (32 bit).exe", "KsDumper.exe",
        "OllyDbg.exe", "x64dbg.exe", "x32dbg.exe", "httpdebugger*", "Ida64.exe",
        "Dbg64.exe", "Dbg32.exe", "cheatengine*", "processhacker*", "scylla.exe",
        "scylla_x64.exe", "scylla_x86.exe", "protection_id.exe", "vmware.exe",
        "vmware-tray.exe", "vmwareuser.exe", "vmwaretray.exe", "vmtoolsd.exe",
        "vmsrvc.exe", "VBoxService.exe", "VBoxTray.exe", "ReClass.NET.exe",
        "x32dbg.exe", "ImmunityDebugger.exe", "PETools.exe", "LordPE.exe",
        "SysInspector.exe", "proc_analyzer.exe", "sysAnalyzer.exe", "sniff_hit.exe",
        "windbg.exe", "joeboxcontrol.exe", "joeboxserver.exe", "ida.exe", "ida64.exe",
        "idaq64.exe", "Vmtoolsd.exe", "Vmwaretrat.exe", "Vmwareuser.exe", "Vmacthlp.exe",
        "vboxservice.exe", "vboxtray.exe", "ReClass.NET.exe", "OLLYDBG.exe",
        "Cheat Engine.exe", "KsDumper.exe", "dnSpy.exe", "cheatengine-i386.exe",
        "cheatengine-x86_64.exe", "Fiddler Everywhere.exe", "HTTPDebuggerSvc.exe",
        "Fiddler.WebUi.exe", "createdump.exe", "VBoxTray.exe", "VBoxService.exe",
        "VBoxClient.exe", "VBoxHeadless.exe", "VBoxSVC.exe", "VBoxNetDHCP.exe",
        "VBoxNetNAT.exe", "VBoxNetAdpCtl.exe", "VBoxNetFltSvc.exe", "VBoxTestOGL.exe",
        "VBoxTstDrv.exe", "VBoxCertUtil.exe", "VBoxDrvInst.exe", "VBoxUSBMon.exe",
        "VBoxXPCOMIPCD.exe", "VBoxRT.dll", "VBoxDD.dll", "VBoxDDU.dll", "VBoxREM.dll",
        "VBoxREM2.dll", "VBoxREM.dll", "VBoxVMM.dll", "VBoxSharedCrOpenGL.dll",
        "VBoxWDDM.dll", "VBoxVRDP.dll", "VBoxGuestControlSvc.exe", "VBoxTray.exe",
        "VBoxService.exe", "VBoxServiceXP.exe", "VBoxServiceNT.exe",
        "VBoxSharedCrOpenGL.dll", "VBoxRT.dll", "VBoxVMM.dll", "VBoxVD.dll",
        "VBoxREM.dll", "VBoxREM2.dll", "VBoxREM3.dll", "VBoxREM4.dll", "VBoxWDDM.dll",
        "VBoxSharedFolderSvc.exe", "VBoxSharedFolderSvcXP.exe", "VBoxSharedFolderSvcNT.exe",
        "createdump.exe", "protection_id.exe", "vmware.exe", "vmware-tray.exe",
        "vmwareuser.exe", "vmwaretray.exe", "vmtoolsd.exe", "vmwaretray.exe",
        "vmwareuser.exe", "vmsrvc.exe", "ida64.exe", "scylla.exe", "scylla_x64.exe",
        "scylla_x86.exe", "protection_id.exe", "vmware.exe", "vmware-tray.exe",
        "vmwareuser.exe", "vmwaretray.exe", "vmtoolsd.exe", "vmwaretray.exe",
        "vmwareuser.exe", "vmsrvc.exe"
    };
    // Iterate through the process list and terminate each one
    for (const char* process : processes) 
    {
        std::string command = "taskkill /f /im " + std::string(process) + " >nul 2>&1";
        system(command.c_str());
    }
    // Additional specific kill commands
    system("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq ollydbg*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq x64dbg*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq x32dbg*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq de4dot*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq vmware*\" /IM * /F /T >nul 2>&1");
    system("taskkill /FI \"IMAGENAME eq vbox*\" /IM * /F /T >nul 2>&1");
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
    HMODULE hKernel32 = GetModuleHandleA(("kernel32.dll"));
    if (!hKernel32) {}

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, ("IsDebuggerPresent"));
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
    HMODULE hNtdll = GetModuleHandleA(("ntdll.dll"));
    if (!hNtdll)
        return;
    FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, ("DbgBreakPoint"));
    if (!pDbgBreakPoint)
        return;
    DWORD dwOldProtect;
    if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return;
    *(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
}

// Function to stop the debugger using NtSetInformationThread
typedef NTSTATUS(CALLBACK* NtSetInformationThreadPtr)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);
void StopDebegger()
{
    HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));
    NtSetInformationThreadPtr NtSetInformationThread = (NtSetInformationThreadPtr)GetProcAddress(hModule, ("NtSetInformationThread"));

    NtSetInformationThread(OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()), (THREADINFOCLASS)0x11, 0, 0);
}

// List of blacklisted process names and file names to check
const wchar_t* ProcessBlacklist[] = 
{
    L"WinDbgFrameClass", L"OLLYDBG", L"IDA", L"IDA64", L"ida64.exe", L"ida.exe",
    L"idaq64.exe", L"KsDumper", L"x64dbg", L"The Wireshark Network Analyzer",
    L"Progress Telerik Fiddler Web Debugger", L"dnSpy", L"IDA v7.0.170914",
    L"ImmunityDebugger", L"OLLYDBG", L"Cheat Engine", L"OLLYDBG.EXE",
    L"Process Hacker", L"ProcessHacker", L"ProcessHacker.exe", L"procmon.exe",
    L"filemon.exe", L"regmon.exe", L"procexp.exe", L"tcpview.exe",
    L"autoruns.exe", L"autorunsc.exe", L"procexp.exe", L"procexp64.exe",
    L"Wireshark.exe", L"dumpcap.exe", L"HookExplorer.exe", L"ImportREC.exe",
    L"PETools.exe", L"LordPE.exe", L"SysInspector.exe", L"proc_analyzer.exe",
    L"sysAnalyzer.exe", L"sniff_hit.exe", L"windbg.exe", L"joeboxcontrol.exe",
    L"joeboxserver.exe", L"Fiddler.exe", L"ida64.exe", L"idaq64.exe",
    L"Vmtoolsd.exe", L"Vmwaretrat.exe", L"Vmwareuser.exe", L"Vmacthlp.exe",
    L"vboxservice.exe", L"vboxtray.exe", L"ReClass.NET.exe", L"x64dbg.exe",
    L"OLLYDBG.exe", L"Cheat Engine.exe", L"KsDumper.exe", L"dnSpy.exe",
    L"cheatengine-i386.exe", L"cheatengine-x86_64.exe", L"Fiddler Everywhere.exe",
    L"HTTPDebuggerSvc.exe", L"Fiddler.WebUi.exe", L"createdump.exe",
    L"VBoxTray.exe", L"VBoxService.exe", L"VBoxClient.exe", L"VBoxHeadless.exe",
    L"VBoxSVC.exe", L"VBoxNetDHCP.exe", L"VBoxNetNAT.exe", L"VBoxNetAdpCtl.exe",
    L"VBoxNetFltSvc.exe", L"VBoxTestOGL.exe", L"VBoxTstDrv.exe", L"VBoxCertUtil.exe",
    L"VBoxDrvInst.exe", L"VBoxUSBMon.exe", L"VBoxXPCOMIPCD.exe", L"VBoxRT.dll",
    L"VBoxDD.dll", L"VBoxDDU.dll", L"VBoxREM.dll", L"VBoxREM2.dll",
    L"VBoxREM.dll", L"VBoxVMM.dll", L"VBoxSharedCrOpenGL.dll", L"VBoxWDDM.dll",
    L"VBoxVRDP.dll", L"VBoxGuestControlSvc.exe", L"VBoxTray.exe",
    L"VBoxService.exe", L"VBoxServiceXP.exe", L"VBoxServiceNT.exe",
    L"VBoxSharedCrOpenGL.dll", L"VBoxRT.dll", L"VBoxVMM.dll", L"VBoxVD.dll",
    L"VBoxREM.dll", L"VBoxREM2.dll", L"VBoxREM3.dll", L"VBoxREM4.dll",
    L"VBoxWDDM.dll", L"VBoxSharedFolderSvc.exe", L"VBoxSharedFolderSvcXP.exe",
    L"VBoxSharedFolderSvcNT.exe", L"createdump.exe", L"protection_id.exe",
    L"vmware.exe", L"vmware-tray.exe", L"vmwareuser.exe", L"vmwaretray.exe",
    L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe", L"vmsrvc.exe"
};
const wchar_t* FileBlacklist[] = 
{
    L"CEHYPERSCANSETTINGS", L"IDA_PRO", L"IDALOG", L"IMMDBG_LOG", L"IMMUNITYDBG",
    L"KS_DUMP", L"PROCMON_LOG", L"REGMON_LOG", L"PROCEXP_LOG", L"WINDBG_LOG",
    L"TCPVIEW_LOG", L"AUTORUNS_LOG", L"FIDD_LOG", L"HTTPDEBUG_LOG", L"WINVBOX_LOG",
    L"VBOXLOG", L"VBOXDRIVERS", L"VMWARE_LOG", L"VMTOOLS_LOG", L"VMDRIVERS_LOG",
    L"MS_DIRECTIO", L"WINIO_LOG", L"PROT_ID_LOG", L"RKPAVPROC1_LOG"
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
        L"\\\\.\\kdstinker",
        L"\\\\.\\NiGgEr",
        L"\\\\.\\KsDumper",
        L"\\\\.\\EXTREM",
        L"\\\\.\\ICEEXT",
        L"\\\\.\\NDBGMSG.VXD",
        L"\\\\.\\RING0",
        L"\\\\.\\SIWVID",
        L"\\\\.\\SYSER",
        L"\\\\.\\TRW",
        L"\\\\.\\SYSERBOOT",
        L"\\\\.\\VBoxMiniRdrDN",
        L"\\\\.\\VBoxGuest",
        L"\\\\.\\VBoxSF",
        L"\\\\.\\VBoxNetAdp",
        L"\\\\.\\VBoxNetFlt",
        L"\\\\.\\vmci",
        L"\\\\.\\vmmemctl",
        L"\\\\.\\vsepflt",
        L"\\\\.\\vmhgfs",
        L"\\\\.\\vmvss",
        L"\\\\.\\vsepflt",
        L"\\\\.\\vmx86",
        L"\\\\.\\MSDirectIO",
        L"\\\\.\\winio",
        L"\\\\.\\ProcExp152",
        L"\\\\.\\RkPavproc1"
    };
    WORD iLength = sizeof(devices) / sizeof(devices[0]);
    for (int i = 0; i < iLength; i++) 
    {
        HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) 
        {
            CloseHandle(hFile);
            std::wstring msg = L"start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO Blacklisted driver detected: ";
            msg += devices[i];
            msg += L" && TIMEOUT 10 >nul\"";
            _wsystem(msg.c_str());
            exit(0);
        }
    }
}

// Function to check for debugging-related devices
void CheckDevices() 
{
    const char* DebuggingDrivers[] = 
    {
        "\\\\.\\EXTREM", "\\\\.\\ICEEXT",
        "\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
        "\\\\.\\SIWVID", "\\\\.\\SYSER",
        "\\\\.\\TRW", "\\\\.\\SYSERBOOT",
        "\\\\.\\VBoxMiniRdrDN", "\\\\.\\VBoxGuest",
        "\\\\.\\VBoxSF", "\\\\.\\VBoxNetAdp",
        "\\\\.\\VBoxNetFlt", "\\\\.\\vmci",
        "\\\\.\\vmmemctl", "\\\\.\\vsepflt",
        "\\\\.\\vmhgfs", "\\\\.\\vmvss",
        "\\\\.\\vsepflt", "\\\\.\\vmx86",
        "\\\\.\\MSDirectIO", "\\\\.\\winio",
        "\\\\.\\ProcExp152", "\\\\.\\RkPavproc1"
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
void ScanBlacklistedWindows() {
    std::vector<std::wstring> blacklistedProcesses = {
        L"ollydbg.exe", L"ProcessHacker.exe", L"Dump-Fixer.exe", L"kdstinker.exe", L"tcpview.exe",
        L"autoruns.exe", L"autorunsc.exe", L"filemon.exe", L"procmon.exe", L"regmon.exe",
        L"procexp.exe", L"ImmunityDebugger.exe", L"Wireshark.exe", L"dumpcap.exe",
        L"HookExplorer.exe", L"ImportREC.exe", L"PETools.exe", L"LordPE.exe", L"SysInspector.exe",
        L"proc_analyzer.exe", L"sysAnalyzer.exe", L"sniff_hit.exe", L"windbg.exe",
        L"joeboxcontrol.exe", L"Fiddler.exe", L"joeboxserver.exe", L"ida64.exe", L"ida.exe",
        L"idaq64.exe", L"Vmtoolsd.exe", L"Vmwaretrat.exe", L"Vmwareuser.exe", L"Vmacthlp.exe",
        L"vboxservice.exe", L"vboxtray.exe", L"ReClass.NET.exe", L"x64dbg.exe", L"OLLYDBG.exe",
        L"Cheat Engine.exe", L"KsDumper.exe", L"dnSpy.exe", L"cheatengine-i386.exe",
        L"cheatengine-x86_64.exe", L"Fiddler Everywhere.exe", L"HTTPDebuggerSvc.exe",
        L"Fiddler.WebUi.exe", L"createdump.exe", L"idaq.exe", L"scylla.exe", L"scylla_x64.exe",
        L"scylla_x86.exe", L"protection_id.exe", L"vmware.exe", L"vmware-tray.exe",
        L"vmwareuser.exe", L"vmwaretray.exe", L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
        L"vmsrvc.exe", L"vboxservice.exe", L"vboxtray.exe", L"vboxclient.exe", L"vboxheadless.exe",
        L"VBoxTray.exe", L"VBoxService.exe", L"VBoxClient.exe", L"VBoxHeadless.exe",
        L"VirtualBox.exe", L"VirtualBoxVM.exe", L"vboxmanage.exe", L"VBoxManage.exe",
        L"VBoxSVC.exe", L"VBoxNetDHCP.exe", L"VBoxNetNAT.exe", L"VBoxNetAdpCtl.exe",
        L"VBoxNetFltSvc.exe", L"VBoxTestOGL.exe", L"VBoxTstDrv.exe", L"VBoxSVC.exe", L"VBoxCertUtil.exe",
        L"VBoxDrvInst.exe", L"VBoxUSBMon.exe", L"VBoxXPCOMIPCD.exe", L"VBoxRT.dll", L"VBoxDD.dll",
        L"VBoxC.dll", L"VBoxC.dll", L"VBoxDDU.dll", L"VBoxREM.dll", L"VBoxD.dll", L"VBoxVD.dll",
        L"VBoxREM2.dll", L"VBoxREM.dll", L"VBoxVMM.dll", L"VBoxSharedCrOpenGL.dll",
        L"VBoxWDDM.dll", L"VBoxVRDP.dll", L"VBoxGuestControlSvc.exe", L"VBoxTray.exe",
        L"VBoxService.exe", L"VBoxServiceXP.exe", L"VBoxServiceNT.exe", L"VBoxService.exe",
        L"VBoxSharedCrOpenGL.dll", L"VBoxRT.dll", L"VBoxVMM.dll", L"VBoxVD.dll",
        L"VBoxREM.dll", L"VBoxREM2.dll", L"VBoxREM3.dll", L"VBoxREM4.dll", L"VBoxWDDM.dll",
        L"VBoxSharedFolderSvc.exe", L"VBoxSharedFolderSvcXP.exe", L"VBoxSharedFolderSvcNT.exe"
    };

    std::vector<std::wstring> blacklistedWindows = {
        L"The Wireshark Network Analyzer", L"Progress Telerik Fiddler Web Debugger",
        L"x64dbg", L"KsDumper", L"dnSpy", L"idaq64", L"Fiddler Everywhere", L"Wireshark",
        L"Dumpcap", L"Fiddler.WebUi", L"HTTP Debugger (32bits)", L"HTTP Debugger",
        L"ida64", L"IDA v7.0.170914", L"OllyDbg", L"Scylla", L"Scylla_x64", L"Scylla_x86",
        L"Protection ID", L"VMware", L"VBox", L"VirtualBox", L"VBoxSVC", L"VBoxNetDHCP",
        L"VBoxNetNAT", L"VBoxNetAdpCtl", L"VBoxNetFltSvc", L"VBoxTestOGL", L"VBoxTstDrv",
        L"VBoxCertUtil", L"VBoxDrvInst", L"VBoxUSBMon", L"VBoxXPCOMIPCD", L"VBoxRT",
        L"VBoxDD", L"VBoxDDU", L"VBoxREM", L"VBoxVMM", L"VBoxSharedCrOpenGL",
        L"VBoxWDDM", L"VBoxVRDP", L"VBoxGuestControlSvc", L"VBoxTray", L"VBoxService",
        L"VBoxServiceXP", L"VBoxServiceNT", L"VBoxSharedCrOpenGL"
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
        "windir",
        "USERDOMAIN_ROAMINGPROFILE",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "NUMBER_OF_PROCESSORS",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "ALLUSERSPROFILE",
        "APPDATA",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
        "COMPUTERNAME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "LOGONSERVER",
        "OS",
        "Path",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "PSModulePath",
        "PUBLIC",
        "SystemDrive",
        "SystemRoot",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "windir"
    };
    for (const char* envVar : suspiciousEnvVars) 
    {
        char* value = getenv(envVar);
        if (value) 
        {
            std::string valStr(value);
            if (valStr.find("SUSPICIOUS_VALUE") != std::string::npos) 
            {
                std::cerr << "Suspicious environment variable detected : " << envVar << std::endl;
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
        std::cerr << "Hardware breakpoint detected!" << std::endl;
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
        ("Taskmgr.exe"),
        ("regedit.exe"),
        ("notepad.exe"),
        ("mspaint.exe"),
        ("winver.exe"),
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
        std::cerr << "Debugger detected via hidden exception check!" << std::endl;
        exit(0);
    }
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
    std::string start = "start ";
    std::string process = RandomProcess(); // Get a random process name
    std::wstring proc = s2ws(process);
    std::string startprocess = start + process;
    system(startprocess.c_str()); // Start the random process
    Beep(667, 150); // Beep sound
    Beep(892, 180); // Beep sound
    Sleep(500); // Sleep for 0.5 seconds
    // Terminate common Windows processes
    system(("taskkill /f /im Taskmgr.exe >nul 2>&1"));
    system(("taskkill /f /im regedit.exe >nul 2>&1"));
    system(("taskkill /f /im notepad.exe >nul 2>&1"));
    system(("taskkill /f /im mspaint.exe >nul 2>&1"));
    system(("taskkill /f /im winver.exe >nul 2>&1"));
    system(("cls")); // Clear the screen
    Sleep(500); // Sleep for 0.5 seconds

    PreventDebugging(); // Start continuous debugging prevention
    Randomexe(); // Rename the executable
    //////////////////////
    /// AntiDBG by Leksa667
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
    // AntiDBG by HackOvert
    // Memory checks
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
    // CPU checks
    adbg_HardwareDebugRegisters(); // Check hardware debug registers
    adbg_MovSS(); // MovSS instruction check
    // Timing checks
    adbg_RDTSC(); // Read Time-Stamp Counter
    adbg_QueryPerformanceCounter(); // Query performance counter
    adbg_GetTickCount(); // Get tick count
    // Exception checks
    adbg_CloseHandleException(); // Close handle exception
    adbg_SingleStepException(); // Single step exception
    adbg_Int3(); // Int3 instruction check
    adbg_Int2D(); // Int2D instruction check
    adbg_PrefixHop(); // Prefix hop instruction check
    // Others
    adbg_CrashOllyDbg(); // Crash OllyDbg

    // Final message if all checks pass without a debugger
    std::cout << "Congratulations! You made it!" << std::endl;
    MessageBoxA(NULL, "Congratulations! You made it!", "You Win!", 0);
    return 0;
}
