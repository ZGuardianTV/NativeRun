#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")

#define info(msg, ...) fprintf(stdout, "[+] " msg, ##__VA_ARGS__)
#define error(msg, ...) fprintf(stderr, "[-] " msg, ##__VA_ARGS__)

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Length;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	BYTE reserved[64];
} _RTL_USER_PROCESS_INFORMATION, * PRL_USER_PROCESS_INFORMATION;


NTSTATUS NTAPI RtlCreateUserProcess(
	__in PUNICODE_STRING NtImagePathName,
	__in ULONG Attributes,
	__in PVOID ProcessParameters,
	__in_opt PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
	__in_opt PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	__in_opt HANDLE ParentProcess,
	__in BOOLEAN InheritHandles,
	__in_opt HANDLE DebugPort,
	__in_opt HANDLE TokenHandle,
	__out PRL_USER_PROCESS_INFORMATION ProcessInformation
);
NTSTATUS NTAPI RtlCreateProcessParameters(
	__deref_out PVOID* pProcessParameters,
	__in PUNICODE_STRING ImagePathName,
	__in_opt PUNICODE_STRING DllPath,
	__in_opt PUNICODE_STRING CommandLine,
	__in_opt PVOID Enviroment,
	__in_opt PUNICODE_STRING WindowTitle,
	__in_opt PUNICODE_STRING DesktopInfo,
	__in_opt PUNICODE_STRING ShellInfo,
	__in_opt PUNICODE_STRING RuntimeData
);

int wmain(int argc, const wchar_t* argv[]) {

	if (argc < 2) {

		error("Invalid usage!\n");
		info("Usage: nativerun <image path> [parameters]\n");
		return -1;
	}

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, argv[1]);

	_RTL_USER_PROCESS_INFORMATION information;
	PVOID params;

	auto status = RtlCreateProcessParameters(&params, &name, NULL, NULL, &name,
		NULL,
		NULL,
		NULL,
		NULL);

	if (!NT_SUCCESS(status)) {
		error("Error (NTSTATUS=0x%00X)\n", status);
		return -1;
	}

	status = RtlCreateUserProcess(&name, 0, params, NULL, NULL, NULL, 0, NULL, NULL, &information);

	if (!NT_SUCCESS(status)) {
		error("Error (status=0x%00X)\n", status);
		return -1;
	}

	info("Process 0x%p created!\n", information.ClientId.UniqueProcess);

	ResumeThread(information.Thread);
	info("Resumed Thread 0x%p", information.Thread);

	return 0;
}