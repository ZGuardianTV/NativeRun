#include "util.h"

#pragma comment(lib, "ntdll")

int wmain(int argc, const wchar_t* argv[]) {

	if (argc < 2) {

		error("Invalid usage!\n");
		info("Usage: %ls <image path> [parameters]\n", argv[0]);
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
		const char* msg = (const char*)ConvertNTSTATUSToString(status);
		error("%s", msg);
		error("(NTSTATUS=0x%00X)\n", status);
		return -1;
	}

	status = RtlCreateUserProcess(&name, 0, params, NULL, NULL, NULL, 0, NULL, NULL, &information);

	if (!NT_SUCCESS(status)) {
		const char* msg = (const char*)ConvertNTSTATUSToString(status);
		error("%s", msg);
		error("(NTSTATUS=0x%00X)\n", status);
		return -1;
	}

	info("Process 0x%p created!\n", information.ClientId.UniqueProcess);

	ResumeThread(information.Thread);
	info("Resumed Thread 0x%p", information.Thread);

	return 0;
}