#include "util.h"

// Stolen From https://stackoverflow.com/questions/25566234/how-to-convert-specific-ntstatus-value-to-the-hresult
DWORD ConvertNtStatusToWin32Error(NTSTATUS status) {
	DWORD oldError;
	DWORD result;
	DWORD br;
	OVERLAPPED o;

	o.Internal = status;
	o.InternalHigh = 0;
	o.Offset = 0;
	o.OffsetHigh = 0;
	o.hEvent = 0;
	oldError = GetLastError();
	GetOverlappedResult(NULL, &o, &br, FALSE);
	result = GetLastError();
	SetLastError(oldError);

	return result;
}

// Stolen from https://stackoverflow.com/questions/1387064/how-to-get-the-error-message-from-the-error-code-returned-by-getlasterror
LPSTR GetLastErrorAsString(DWORD errorMessageID) {

	LPSTR messageBuffer = NULL;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = (size_t)FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);


	return messageBuffer;
}

LPSTR ConvertNTSTATUSToString(NTSTATUS status) {
	return GetLastErrorAsString(ConvertNtStatusToWin32Error(status));
}