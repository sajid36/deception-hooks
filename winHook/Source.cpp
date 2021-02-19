#include "stdafx.h"
#define WIN32_LEAN_AND_MEAN

#include <easyhook.h>
#include <string>
#include <iostream>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "8888"
#define DEFAULT_IP "localhost"

using namespace std;
DWORD gFreqOffset = 0;
HANDLE sensitiveFile;
HANDLE sourceHandle;
HANDLE targetHandle;
vector<pair<HANDLE, HANDLE>> pipePair;
int pipeCreated=0;
HANDLE pipeReadHandle = NULL;

string honey(string api, string param1) {
	cout << "inside send" << endl;
	string reply = "";
	char server_reply[2000];
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	string request = "api: "+api+", param1: "+param1;
	const char *sendbuf = "Init";
	char recvbuf[DEFAULT_BUFLEN];
	int iResult;
	int recvbuflen = DEFAULT_BUFLEN;

	// Validate the parameters

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return "failed";
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(DEFAULT_IP, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return "failed";
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return "failed";
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	puts("Connected");

	//Send some data
//	char *message = new char[request.length()-1];
	//strcpy(message, request.c_str());
	// do stuff

	//message = "this is from client";
	if (send(ConnectSocket, request.c_str(), strlen(request.c_str()), 0) < 0)
	{
		puts("Send failed");
		return "failed";
	}
	puts("Data Send\n");

	//Receive a reply from the server
	if ((iResult = recv(ConnectSocket, server_reply, 2000, 0)) == SOCKET_ERROR)
	{
		puts("recv failed");
	}

	puts("Reply received\n");

	//Add a NULL terminating character to make it a proper string before printing
	//Add a NULL terminating character to make it a proper string before printing
	server_reply[iResult] = '\0';
	cout << "server reply: " << server_reply << endl;
	reply = server_reply;
	closesocket(ConnectSocket);
	WSACleanup();
	return reply;
}


HANDLE WINAPI myCreateFileWHook(LPCWSTR lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile)
{
	std::cout << "-> CreateFileW Hook: ****All your CreateFileW belong to us!\n\n";
	std::wstring lpName = lpFileName;

	wstring ws(lpFileName);
	string fileName = string(ws.begin(), ws.end());
	cout << fileName << endl;

	HANDLE oFile = CreateFileW(lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	if (fileName.find("txt") != std::string::npos) {
		cout << "found sensitive file" << endl;
		sensitiveFile = oFile;
	}
	cout << "handle: " << oFile << endl;
	return oFile;
}


BOOL WINAPI myReadFile(HANDLE hFile,
	char       *lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped)
{
	//if (readFileSwitch != 1) {
	std::cout << "\n    ReadFile Hook: ****All your ReadFile belong to us!\n\n";
	wcout << hFile << "\n";
	wcout << lpBuffer << "\n";
	wcout << nNumberOfBytesToRead << "\n";
	wcout << lpNumberOfBytesRead << "\n";
	wcout << lpOverlapped << "\n";

	if (hFile == sensitiveFile) {
		// the target program is accessing sentive file (here it's a text file)
		//call the actually readfile to check how many bytes it want to read?
		ReadFile(hFile,
			lpBuffer,
			nNumberOfBytesToRead,
			lpNumberOfBytesRead,
			lpOverlapped);
		// *lpNumberOfBytesRead holds number of bytes to be read. 
		// if we don't care about the size, we don't need to call ReadFile, We can directly memcpy our provided char array/string
		if (*lpNumberOfBytesRead > 1) {
			cout << "connect to honey server to alter content " << endl;
			char *content = "this is altered content ";

			// check for error and size of the returned buffer.
			memcpy(lpBuffer, content, strlen(content));
			*lpNumberOfBytesRead = strlen(content);
			return TRUE;
		}
	}

	if (hFile == pipeReadHandle) {
		// the target program is accessing sentive file (here it's a text file)
		//call the actually readfile to check how many bytes it want to read?
		ReadFile(hFile,
			lpBuffer,
			nNumberOfBytesToRead,
			lpNumberOfBytesRead,
			lpOverlapped);
		// *lpNumberOfBytesRead holds number of bytes to be read. 
		// if we don't care about the size, we don't need to call ReadFile, We can directly memcpy our provided char array/string
		if (*lpNumberOfBytesRead > 1) {
			cout << "connect to honey server to alter content " << endl;
			char *content = "altered ";

			// check for error and size of the returned buffer.
			memcpy(lpBuffer, content, strlen(content));
			*lpNumberOfBytesRead = strlen(content);
			return TRUE;
		}
	}

	else {
		BOOL readFileStatus = ReadFile(hFile,
			lpBuffer,
			nNumberOfBytesToRead,
			lpNumberOfBytesRead,
			lpOverlapped);
		//printf("readfile buffer = %s\n", lpBuffer);
		//cout << "*****end of readfile******" << endl;
		return readFileStatus;
	}

}
DWORD WINAPI myGetCurrentDirectoryW(DWORD  nBufferLength,
	LPTSTR lpBuffer)
{
	string honeyReply = honey("GetCurrentDirectoryW", "None");
	DWORD returnLength  = honeyReply.length();

	int i;
	for (i = 0; i<honeyReply.length(); i++)
	{
		lpBuffer[i] = honeyReply[i];
	}
	lpBuffer[i++] = '\0';
	std::cout << "\n    GetCurrentDirectory Hook: ****All your GetCurrentDirectory belong to us!\n\n";
	return returnLength;
}

BOOL WINAPI myCreateProcessHook(LPCWSTR lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	std::cout << "\n    BeepHook: ****All your CreateProcess belong to us!\n\n";
	
	if (pipeCreated >= 2) {
		pipeReadHandle = pipePair[0].first;
		cout << "pipeReadHandle: " << pipeReadHandle << endl;
	}
	cout << "pipePair.size(): " << pipePair.size() << endl;
	while (!pipePair.empty())
	{
		pipePair.pop_back();
	}
	
	BOOL CreateProcessStatus = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	cout << lpStartupInfo << endl;
	cout << "end of CreateProcessHook" << endl;
	pipeCreated = 0;
	return CreateProcessStatus;

}

/*BOOL WINAPI myDuplicateHandle(HANDLE   hSourceProcessHandle,
	HANDLE   hSourceHandle,
	HANDLE   hTargetProcessHandle,
	LPHANDLE lpTargetHandle,
	DWORD    dwDesiredAccess,
	BOOL     bInheritHandle,
	DWORD    dwOptions)
{
	std::cout << "\n    BeepHook: ****All your DuplicateHandle belong to us!\n\n";

	sourceHandle = hSourceHandle;
	targetHandle = hTargetProcessHandle;

	cout << hSourceHandle << endl;
	cout << hTargetProcessHandle << endl;

	return DuplicateHandle(hSourceProcessHandle,
		hSourceHandle,
		hTargetProcessHandle,
		lpTargetHandle,
		dwDesiredAccess,
		bInheritHandle,
		dwOptions);
	
}*/

BOOL WINAPI myCreatePipe(PHANDLE hReadPipe,
	PHANDLE hWritePipe,
	LPSECURITY_ATTRIBUTES lpPipeAttributes,
	DWORD nSize)
{
	std::cout << "\n    BeepHook: ****All your CreatePipe belong to us!\n\n";
	BOOL CreatePipeStatus =  CreatePipe(
		hReadPipe,
		hWritePipe,
		lpPipeAttributes,
		nSize
	);

	HANDLE readHandle = *hReadPipe;
	HANDLE writeHandle = *hWritePipe;
	cout << "readHandle: " << readHandle << endl;
	cout << "writeHandle: " << writeHandle << endl;

	pipePair.push_back(std::make_pair(readHandle, writeHandle));
	pipeCreated++;
	return CreatePipeStatus;
}

BOOL WINAPI myBeepHook(DWORD dwFreq, DWORD dwDuration)
{
	std::cout << "\n    BeepHook: ****All your beeps belong to us!\n\n";
	string reply = honey("Beep", "");
	cout << "inside BEEP" << endl;
	cout << reply << endl;
	return Beep(dwFreq + gFreqOffset, dwDuration);
}

// EasyHook will be looking for this export to support DLL injection. If not found then 
// DLL injection will fail.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	/*std::cout << "\n\nNativeInjectionEntryPointt(REMOTE_ENTRY_INFO* inRemoteInfo)\n\n" <<
		"IIIII           jjj               tt                dd !!! \n"
		" III  nn nnn          eee    cccc tt      eee       dd !!! \n"
		" III  nnn  nn   jjj ee   e cc     tttt  ee   e  dddddd !!! \n"
		" III  nn   nn   jjj eeeee  cc     tt    eeeee  dd   dd     \n"
		"IIIII nn   nn   jjj  eeeee  ccccc  tttt  eeeee  dddddd !!! \n"
		"              jjjj                                         \n\n";*/

	//std::cout << "Injected by process Id: " << inRemoteInfo->HostPID << "\n";
	//std::cout << "Passed in data size: " << inRemoteInfo->UserDataSize << "\n";
	if (inRemoteInfo->UserDataSize == sizeof(DWORD))
	{
		gFreqOffset = *reinterpret_cast<DWORD *>(inRemoteInfo->UserData);
	}

	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook
	HOOK_TRACE_INFO hHookGetCurrentDirectoryW = { NULL };
	HOOK_TRACE_INFO hHookReadFile = { NULL };
	HOOK_TRACE_INFO hHookCreateFileW = { NULL };
	HOOK_TRACE_INFO hHookCreateProcessW = { NULL };
	//HOOK_TRACE_INFO hHookDuplicateHandle= { NULL };
	HOOK_TRACE_INFO hHookCreatePipe = { NULL };

	//std::cout << "\n";
	//std::cout << "Win32 Beep found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep") << "\n";
	//std::cout << "Win32 GetCurrentDirectoryW found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetCurrentDirectoryW") << "\n";
	//std::cout << "Win32 ReadFile found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFile") << "\n";
	//std::cout << "Win32 CreateFileW found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileW") << "\n";
	//std::cout << "Win32 CreateProcessW found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateProcessW") << "\n";

	// Install the hook
	NTSTATUS result = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep"),
		myBeepHook,
		NULL,
		&hHook);
	NTSTATUS resultGetCurrentDirectoryW = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetCurrentDirectoryW"),
		myGetCurrentDirectoryW,
		NULL,
		&hHookGetCurrentDirectoryW);
	NTSTATUS resultReadFile = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFile"),
		myReadFile,
		NULL,
		&hHookReadFile);
	NTSTATUS resultCreateFileW = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileW"),
		myCreateFileWHook,
		NULL,
		&hHookCreateFileW);
	NTSTATUS resultCreateProcessW = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateProcessW"),
		myCreateProcessHook,
		NULL,
		&hHookCreateProcessW);
	/*NTSTATUS resultDuplicateHandle = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "DuplicateHandle"),
		myDuplicateHandle,
		NULL,
		&hHookDuplicateHandle);*/
	NTSTATUS resultCreatePipe = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreatePipe"),
		myCreatePipe,
		NULL,
		&hHookCreatePipe);

	if (/*FAILED(resultDuplicateHandle) &&*/ FAILED(resultCreatePipe) && FAILED(resultCreateProcessW) && FAILED(resultCreateFileW) && FAILED(resultReadFile) && FAILED(resultGetCurrentDirectoryW) && FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		std::wcout << "Failed to install hook: ";
		std::wcout << s;
	}
	else
	{
		std::cout << "Hook 'myBeepHook installed successfully.\n";
	}

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &hHook);
	LhSetExclusiveACL(ACLEntries, 1, &hHookGetCurrentDirectoryW);
	LhSetExclusiveACL(ACLEntries, 1, &hHookReadFile);
	LhSetExclusiveACL(ACLEntries, 1, &hHookCreateFileW);
	LhSetExclusiveACL(ACLEntries, 1, &hHookCreateProcessW);
	//LhSetExclusiveACL(ACLEntries, 1, &hHookDuplicateHandle);
	LhSetExclusiveACL(ACLEntries, 1, &hHookCreatePipe);

	return;
}