#pragma once
#include <cinttypes>
#include <Windows.h>
#include <Winternl.h>
#include <string>
#include <filesystem>
#include <stdio.h>
#include <Tlhelp32.h>
#include <vector>
#include <thread>
#include <dwmapi.h>
#include <cstdint>
#include <iostream>
#include <stdint.h>
#include <fstream>
#include <random>
#include <conio.h>

enum DBG_CATCH
{
	DBG_NONE = 0x0000,
	DBG_BEINGEBUGGEDPEB = 0x1000,
	DBG_CHECKREMOTEDEBUGGERPRESENT = 0x1001,
	DBG_ISDEBUGGERPRESENT = 0x1002,
	DBG_NTGLOBALFLAGPEB = 0x1003,
	DBG_NTQUERYINFORMATIONPROCESS = 0x1004,
	DBG_FINDWINDOW = 0x1005,
	DBG_OUTPUTDEBUGSTRING = 0x1006,
	DBG_NTSETINFORMATIONTHREAD = 0x1007,
	DBG_DEBUGACTIVEPROCESS = 0x1008,
	DBG_PROCESSFILENAME = 0x1009,
	DBG_HARDWAREDEBUGREGISTERS = 0x2000,
	DBG_MOVSS = 0x2001,
	DBG_RDTSC = 0x3000,
	DBG_QUERYPERFORMANCECOUNTER = 0x3001,
	DBG_GETTICKCOUNT = 0x3002,
	DBG_CLOSEHANDLEEXCEPTION = 0x4000,
	DBG_SINGLESTEPEXCEPTION = 0x4001,
	DBG_INT3CC = 0x4002,
	DBG_PREFIXHOP = 0x4003,
	DBG_NTCLOSECHECK = 0x5000,
	DBG_CHECKDEBUGREGISTERS = 0x5001,
	DBG_STRCHECKS = 0x5002,
	DBG_PROCESSDEBUGFLAGS = 0x5003,
	DBG_UNHANDLEDEXCEPTIONFILTER = 0x5004,
	DBG_SELFMODIFYINGCODE = 0x5006,
	DBG_COMPLEXANTIREVERSING = 0x5007,
	DBG_TLS_CALLBACK = 0x5008,
	DBG_HEAP_SPRAY = 0x5009,
	DBG_ADVANCED_TIMING_CHECK = 0x5010
};
void DBG_MSG(WORD dbg_code, char* message);

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);

typedef struct timeKeeper {
	uint64_t timeUpperA;
	uint64_t timeLowerA;
	uint64_t timeUpperB;
	uint64_t timeLowerB;
} TimeKeeper;

#ifdef _WIN64
extern "C"
{
	int adbg_BeingDebuggedPEBx64(void);
	int adbg_NtGlobalFlagPEBx64(void);
	void adbg_GetTickCountx64(void);
	void adbg_QueryPerformanceCounterx64(void);
	void adbg_RDTSCx64(TimeKeeper*);
	void adbg_Int2Dx64(void);
	void adbg_Int3x64(void);
	void adbg_SingleStepExceptionx64(void);
};
#endif

void adbg_BeingDebuggedPEB(void);
void adbg_CheckRemoteDebuggerPresent(void);
void adbg_CheckWindowClassName(void);
void adbg_CheckWindowName(void);
void adbg_ProcessFileName(void);
void adbg_IsDebuggerPresent(void);
void adbg_NtGlobalFlagPEB(void);
void adbg_NtQueryInformationProcess(void);
void adbg_NtSetInformationThread(void);
void adbg_DebugActiveProcess(const char*);

void adbg_HardwareDebugRegisters(void);
void adbg_MovSS(void);

void adbg_RDTSC(void);
void adbg_QueryPerformanceCounter(void);
void adbg_GetTickCount(void);

void adbg_CrashOllyDbg(void);

void adbg_CloseHandleException(void);
void adbg_SingleStepException(void);
void adbg_Int3(void);
void adbg_Int2D(void);
void adbg_PrefixHop(void);

void adbg_NtCloseCheck(void);
void adbg_CheckDebugRegisters(void);
void adbg_OutputDebugStringCheck(void);
void adbg_ProcessDebugFlags(void);
void adbg_SetUnhandledExceptionFilter(void);
void adbg_SelfModifyingCode(void);
void adbg_AntiRe(void);
void AdvancedTimingCheck();
void NTAPI TLSCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved);