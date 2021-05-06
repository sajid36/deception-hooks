#include "stdafx.h"
#define WIN32_LEAN_AND_MEAN
#include <easyhook.h>
#include <string>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <shellapi.h>
#pragma comment(lib, "cpprest_2_10")
#include <iostream>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define BUFFERSIZE 5000
#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "8888"
#define DEFAULT_IP "localhost"

//#define DECEPTION_STRAT  1 // FakeFailure (Show failure despite success)
//#define DECEPTION_STRAT  2 // FakeSuccess (Show altered content)
//#define DECEPTION_STRAT  3 // FakeExecute (Get data from honey factory)
//#define DECEPTION_STRAT  4 // NativeExecute (Let attacker perform action)

int Behave = 0;
std::string HoneyServer;
int DECEPTION_STRAT = 0;

using namespace std;
using namespace web;
using namespace web::http;
using namespace web::http::client;
DWORD gFreqOffset = 0;
HANDLE sensitiveFile;
HANDLE sourceHandle;
HANDLE targetHandle;
vector<pair<HANDLE, HANDLE>> pipePair;
int pipeCreated=0;
HANDLE pipeReadHandle = NULL;
int childProcessReadFlag = 0;
std::string response;


struct Config {
	int    Behave;
	string HoneyServer;
	int Strat;
};

void loadConfig(Config& config) {
	ifstream fin("config.txt");
	std::string line;
	while (getline(fin, line)) {
		istringstream sin(line.substr(line.find("=") + 1));
		if (line.find("Behave") != -1)
			sin >> config.Behave;
		else if (line.find("HoneyServer") != -1)
			sin >> config.HoneyServer;
		else if (line.find("Strat") != -1)
			sin >> config.Strat;
	}
}
void display_json(
	json::value const & jvalue,
	utility::string_t const & prefix)
{
	wcout << prefix << jvalue.serialize() << endl;
}

pplx::task<http_response> make_task_request(
	http_client & client,
	method mtd,
	json::value const & jvalue)
{
	return (mtd == methods::GET || mtd == methods::HEAD) ?
		client.request(mtd, L"/victim") :
		client.request(mtd, L"/victim", jvalue);
}

wstring make_request(
	http_client & client,
	method mtd,
	json::value const & jvalue)
{
	wstring res;
	make_task_request(client, mtd, jvalue)
		.then([](http_response response)
	{
		if (response.status_code() == status_codes::OK)
		{
			return response.extract_json();
		}
		return pplx::task_from_result(json::value());
	})
		.then([&](pplx::task<json::value> previousTask)
	{
		try
		{
			display_json(previousTask.get(), L"R: ");
			json::value const & jvalue = previousTask.get();
			utility::string_t jsonval = jvalue.serialize();
			res = jsonval;
		}
		catch (http_exception const & e)
		{
			wcout << e.what() << endl;
		}
	})
		.wait();
	return res;
}

wstring honeyFactory(wstring context, wstring additional) {
	http_client client(U("http://192.168.56.102:5000/"));

	auto postValue = json::value::object();
	postValue[L"context"] = json::value::string(context);
	postValue[L"additional"] = json::value::string(additional);

	wcout << L"\nPOST (get some values)\n";
	display_json(postValue, L"S: ");
	wstring response= make_request(client, methods::POST, postValue);
	wcout << "from honeyFactory: "<< response << endl;
	return response;


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
	std::string fileName = std::string(ws.begin(), ws.end());
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
			//honeyFactory("readfile", "test.txt");

			// check for error and size of the returned buffer.
			memcpy(lpBuffer, content, strlen(content));
			*lpNumberOfBytesRead = strlen(content);
			return TRUE;
		}
	}

	else if (hFile == pipeReadHandle && childProcessReadFlag==1) {


		cout << "///////////////////special case///////////////: " << endl;
		cout << pipeReadHandle << endl;
		cout << childProcessReadFlag << endl;
		childProcessReadFlag = 0;
		FlushFileBuffers(hFile);
		// the target program is accessing sentive file (here it's a text file)
		//call the actually readfile to check how many bytes it want to read?
		BOOL status = ReadFile(hFile,
			lpBuffer,
			nNumberOfBytesToRead,
			lpNumberOfBytesRead,
			lpOverlapped);
		if (*lpNumberOfBytesRead > 1) {

			cout << "memcpy: " << endl;
			cout << response << endl;
			memcpy(lpBuffer, response.c_str(), strlen(response.c_str()));
			*lpNumberOfBytesRead = strlen(response.c_str());


			// *lpNumberOfBytesRead holds number of bytes to be read. 
			// if we don't care about the size, we don't need to call ReadFile, We can directly memcpy our provided char array/string
			return status;
		}
	
	}

	else {
		BOOL readFileStatus = ReadFile(hFile,
			lpBuffer,
			nNumberOfBytesToRead,
			lpNumberOfBytesRead,
			lpOverlapped);
		printf("readfile buffer = %s\n", lpBuffer);
		cout << "*****end of readfile******" << endl;
		return readFileStatus;
	}

}
DWORD WINAPI myGetCurrentDirectoryW(DWORD  nBufferLength,
	LPTSTR lpBuffer)
{
	std::cout << "\n    GetCurrentDirectory Hook: ****All your GetCurrentDirectory belong to us!\n\n";
	if (DECEPTION_STRAT == 1) {
		return 0;
	}
	else if (DECEPTION_STRAT == 2) {

		int i;
		std::string directory = "D:\\Dropbox\\Dropbox\\transfer";
		directory = directory + '\0';
		DWORD returnLength = directory.length();
		for (i = 0; i<directory.length(); i++)
		{
			lpBuffer[i] = directory[i];
		}
		lpBuffer[i++] = '\0';
		return returnLength;
	}
	else if (DECEPTION_STRAT == 3) {

		wstring res = honeyFactory(L"currentDirectory", L" ");
		wcout << "from GetCurrentDirectory hook " << res << endl;


		//string to json
		utility::string_t s = res;
		json::value ret = json::value::parse(s);
		wcout << ret.at(U("currentDirectory")).as_string() << endl;

		wstring wideRes = ret.at(U("currentDirectory")).as_string();

		//wstring to string
		std::string localResponse(wideRes.begin(), wideRes.end());
		response = localResponse;
		response = response + '\0';


		DWORD returnLength = response.length();

		int i;
		for (i = 0; i < response.length(); i++)
		{
			lpBuffer[i] = response[i];
		}
		lpBuffer[i++] = '\0';
		return returnLength;
	}
	else {
		return GetCurrentDirectoryW(nBufferLength,
			lpBuffer);
	}
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

	HANDLE childStdOutput = lpStartupInfo->hStdOutput;
	wcout << "child handle: " << childStdOutput << endl;
	if (pipeCreated >= 1) {
		pipeReadHandle = pipePair[0].first;
		cout << "pipeReadHandle: " << pipeReadHandle << endl;
	}
	cout << "pipePair.size(): " << pipePair.size() << endl;
	while (!pipePair.empty())
	{
		pipePair.pop_back();
	}
	wstring wcommand (lpCommandLine);
	//string command = string(wcommand.begin(), wcommand.end());
	
	wstring res = honeyFactory(L"command", wcommand);
	wcout << "from CreateProcess hook " << res << endl;
	//string to json
	utility::string_t s = res;
	json::value ret = json::value::parse(s);
	wcout << ret.at(U("response")).as_string() << endl;

	wstring wideRes = ret.at(U("response")).as_string();

	//wstring to string
	std::string localResponse(wideRes.begin(), wideRes.end());
	response = localResponse;
	response = response + '\0';


	childProcessReadFlag = 1;
	BOOL CreateProcessStatus = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);


	cout << lpStartupInfo << endl;
	cout << "end of CreateProcessHook" << endl;
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
	cout << "inside BEEP" << endl;
	return Beep(dwFreq + gFreqOffset, dwDuration);
}

HANDLE WINAPI myGetClipboardData(UINT uFormat)
{
	std::cout << "\n    BeepHook: ****All your GetClipboardData belong to us!\n\n";
	//string reply = honey("Beep", "");
	cout << "inside GetClipboardData" << endl;
	HANDLE hData = GetClipboardData(CF_TEXT);
	cout << hData << endl;
	char * pszText = static_cast<char*>(GlobalLock(hData));
	std::string text(pszText);
	cout << "get "<<text << endl;
	GlobalUnlock(hData);
	EmptyClipboard();
	CloseClipboard();



	const char* output = "Test";
	const size_t len = strlen(output) + 1;
	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
	memcpy(GlobalLock(hMem), output, len);
	GlobalUnlock(hMem);
	EmptyClipboard();
	OpenClipboard(0);
	hData = SetClipboardData(CF_TEXT, hMem);
	cout << hData << endl;
	char * pszText1 = static_cast<char*>(GlobalLock(hData));
	std::string text1(pszText1);
	cout << "set " << text1 << endl;
	GlobalUnlock(hData);

	

/*	wchar_t s[] = L"msajid@uncc.edu 123456789";
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, wcslen(s) + 1);
	LPTSTR  lptstrCopy = (LPTSTR)GlobalLock(hglbCopy);
	memcpy(pszText, s,
		wcslen(s));
	lptstrCopy[wcslen(s)] = (TCHAR)0;    // null character 
	GlobalUnlock(hglbCopy);
	hData = SetClipboardData(CF_TEXT, hglbCopy);
	cout << hData << endl;
	char * pszText1 = static_cast<char*>(GlobalLock(hData));
	std::string text1(pszText1);
	cout << "set "<<text1 << endl;
	GlobalUnlock(hData);*/


	HANDLE hData2 = GetClipboardData(CF_TEXT);
	cout << hData2 << endl;
	char * pszText2 = static_cast<char*>(GlobalLock(hData2));
	std::string text2(pszText2);
	cout << "get " << text2 << endl;
	GlobalUnlock(hData2);

	/*
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE,
		(s.length() + 1) * sizeof(TCHAR));

	LPTSTR lptstrCopy = (LPTSTR)GlobalLock(hglbCopy);
	memcpy(lptstrCopy, &s,
		(s.length() + 1) * sizeof(wchar_t));
	lptstrCopy[sizeof(s)] = (TCHAR)0;    // null character 
	GlobalUnlock(hglbCopy);
	SetClipboardData(uFormat, hglbCopy);

	hData = GetClipboardData(uFormat);
	cout << hData << endl;
	char * pszText1 = static_cast<char*>(GlobalLock(hData));
	std::string text1(pszText1);
	cout << text1 << endl;
	GlobalUnlock(hData);*/



	return hData2;
}

BOOL WINAPI myGetComputerNameW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD	nSize)
{
std:cout << "\n    myGetComputerNameWHook: ****All your ComputerNames belong to us!\n\n";
	LPVOID honeyReply;
	switch (NameType) {
	case (ComputerNameNetBIOS):
		honeyReply = "NetBiosName";
	case(ComputerNameDnsHostname):
		honeyReply = "DnsHostName";
	case(ComputerNameDnsDomain):
		honeyReply = "DnsDomaName";
	case(ComputerNameDnsFullyQualified):
		honeyReply = "DnsFulQName";
	case(ComputerNamePhysicalNetBIOS):
		honeyReply = "PhyNetBName";
	case(ComputerNamePhysicalDnsHostname):
		honeyReply = "PhyDnsHName";
	case(ComputerNamePhysicalDnsDomain):
		honeyReply = "PhyDnsDName";
	case(ComputerNamePhysicalDnsFullyQualified):
		honeyReply = "PhyDFQuName";
	case(ComputerNameMax):
		honeyReply = "NameMaxName";
	default:
		honeyReply = "DeHoneYName";
	}

	memcpy(lpBuffer, honeyReply, 11);
	*nSize = 11;
	std::cout << (char *)lpBuffer << endl;
	return true;
}

BOOL WINAPI myGetVersionExA(LPOSVERSIONINFOA lpVersionInformation)
{
std:cout << "\n    myGetVersionExA: ****All your GetVersionExA belong to us!\n\n";
	DWORD majorver = 5;
	DWORD minorver = 2;
	DWORD buildNum = 7699;
	DWORD platid = 0;

	lpVersionInformation->dwOSVersionInfoSize = 156;
	lpVersionInformation->dwMajorVersion = majorver;
	lpVersionInformation->dwMinorVersion = minorver;
	lpVersionInformation->dwBuildNumber = buildNum;
	lpVersionInformation->dwPlatformId = platid;
	strcpy(lpVersionInformation->szCSDVersion, "Service Pack 3");
	//printf("Modified service pack info is: %s", lpVersionInformation->szCSDVersion);

	return true;
}

BOOL WINAPI myShellExecuteExW(SHELLEXECUTEINFO *pExecInfo)
{
std:cout << "\n    myShellExecuteExW: ****All your ShellExecuteExW belong to us!\n\n";

	SHELLEXECUTEINFOW honeyInfo;
	honeyInfo.cbSize = pExecInfo->cbSize;
	honeyInfo.fMask = pExecInfo->fMask;
	honeyInfo.hwnd = pExecInfo->hwnd;
	honeyInfo.lpVerb = pExecInfo->lpVerb;
	honeyInfo.lpParameters = pExecInfo->lpParameters;
	honeyInfo.lpDirectory = pExecInfo->lpDirectory;
	honeyInfo.nShow = pExecInfo->nShow;
	honeyInfo.hInstApp = pExecInfo->hInstApp;
	honeyInfo.lpIDList = pExecInfo->lpIDList;
	honeyInfo.hkeyClass = pExecInfo->hkeyClass;
	honeyInfo.dwHotKey = pExecInfo->dwHotKey;
	honeyInfo.hIcon = pExecInfo->hIcon;
	honeyInfo.hMonitor = pExecInfo->hMonitor;
	honeyInfo.hProcess = pExecInfo->hProcess;

	if (DECEPTION_STRAT == 1) {
		return ERROR_ACCESS_DENIED;
	}
	else if (DECEPTION_STRAT == 2) {
		LPCWSTR honeyFile = L"C:\\Users\\sajid\\Desktop\\honey.txt";
		honeyInfo.lpFile = honeyFile;
		BOOL honeyExecutedFile = ShellExecuteExW(&honeyInfo);

		return honeyExecutedFile;
	}
	else if (DECEPTION_STRAT == 3) {
		wstring res = honeyFactory(L"shellExecute", L" ");
		wcout << "from shellExecute hook " << res << endl;
		//string to json
		utility::string_t str = res;
		json::value ret = json::value::parse(str);
		wcout << ret.at(U("response")).as_string() << endl;

		wstring wideRes = ret.at(U("response")).as_string();
		//wstring to string
		std::string localResponse(wideRes.begin(), wideRes.end());
		response = localResponse;
		response = response + '\0';

		// Convert response string to wide string
		wstring wstr = wstring(response.begin(), response.end());
		//std::replace(wstr.begin(), wstr.end(), '%', '\\');
		wchar_t const * honeyFile = wstr.c_str();
		honeyInfo.lpFile = honeyFile;

		BOOL honeyExecutedFile = ShellExecuteExW(&honeyInfo);
		return honeyExecutedFile;
	}
	return ShellExecuteExW(pExecInfo);
}

int WINAPI mySend(
	SOCKET     s,
	const char *buf,
	int        len,
	int        flags
)
{
	cout << "\n    mySend: ****All your send belong to us!\n\n";
	cout << len << endl;

	std::string sub_str = buf;
	std::string com = "System";
	sub_str = sub_str.substr(1, 6);

	cout << sub_str.compare(com) << endl;

	if (sub_str.compare(com) == 0) {
		if (DECEPTION_STRAT == 1) {
			//string fake(540, ' ');
			//fake.replace(0, 15, "No survey data");
			char * content = "No survey data";
			//const char * fakeFailure = fake.c_str();
			//int honeySend = send(s, fakeFailure, len, flags);
			int honeySend = send(s, content, strlen(content), flags);
			return honeySend;
		}
		else if (DECEPTION_STRAT == 2) {
			const char * fakeFailure = "System Platform     - HoneyS2-0-0.0.0000-SP2\n"
				"Processor           - Honey00 Family 0 Model 000 Stepping 0, GenuineIntel\n"
				"Architecture        - Honey\n"
				"Internal IP         - abc.def.ghi.jkl\n"
				"External IP         - b'00.00.000.00'\n"
				"MAC Address         - 08:00:27:C5:BD:02\n"
				"Internal Hostname   - Honey-PC\n"
				"External Hostname   - 0000.00-000-00.abcdnet.com.00\n"
				"Hostname Aliases    - \n"
				"FQDN                - Honey-PC\n"
				"Current User        - Honey"
				"System Datetime     - Thu, 01 Apr 2021 09:40:10 Pacific Standard Time\n"
				"Admin Access        - No\n"
				"survey completed.";
			int honeySend = send(s, fakeFailure, len, flags);
			return honeySend;
		}
		else if (DECEPTION_STRAT == 3) {
			wstring res = honeyFactory(L"survey", L" ");
			wcout << "from send hook " << res << endl;
			//string to json
			utility::string_t str = res;
			json::value ret = json::value::parse(str);
			wcout << ret.at(U("response")).as_string() << endl;

			wstring wideRes = ret.at(U("response")).as_string();

			//wstring to string
			std::string localResponse(wideRes.begin(), wideRes.end());
			response = localResponse;
			response = response + '\0';
			const char *cstr = response.c_str();

			cout << cstr << endl;

			int honeySend = send(s, cstr, (int)strlen(cstr), flags);
			if (honeySend == SOCKET_ERROR) {
				wprintf(L"send failed with error: %d\n", WSAGetLastError());
				closesocket(s);
				WSACleanup();
				return 1;
			}
			return honeySend;
		}
	}
	return send(s, buf, len, flags);
}

BOOL WINAPI myWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	std:cout << "\n    myWriteFile: ****All your WriteFile belong to us!\n\n";
	if (DECEPTION_STRAT == 1) {
		return false;
	}
	else if (DECEPTION_STRAT == 2) {
		const void* honeyValue = "Static honeyfile  ";
		BOOL honeyWriteFileStatus = WriteFile(
			hFile,
			honeyValue,
			nNumberOfBytesToWrite,
			lpNumberOfBytesWritten,
			lpOverlapped
		);
		return honeyWriteFileStatus;
	}
	else if (DECEPTION_STRAT == 3) {
		wstring res = honeyFactory(L"writeFile", L" ");
		wcout << "from writeFile hook " << res << endl;
		//string to json
		utility::string_t str = res;
		json::value ret = json::value::parse(str);
		wcout << ret.at(U("response")).as_string() << endl;

		wstring wideRes = ret.at(U("response")).as_string();

		//wstring to string
		std::string localResponse(wideRes.begin(), wideRes.end());
		response = localResponse;
		response = response + '\0';
		const void* honeyValue = response.c_str();

		BOOL honeyWriteFileStatus = WriteFile(
			hFile,
			honeyValue,
			nNumberOfBytesToWrite,
			lpNumberOfBytesWritten,
			lpOverlapped
		);
	}
	return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
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
	HOOK_TRACE_INFO hHookReadFile = { NULL };
	HOOK_TRACE_INFO hHookCreateFileW = { NULL };
	HOOK_TRACE_INFO hHookGetCurrentDirectoryW = { NULL };
	HOOK_TRACE_INFO hHookCreateProcessW = { NULL };
	HOOK_TRACE_INFO hHookDuplicateHandle= { NULL };
	HOOK_TRACE_INFO hHookCreatePipe = { NULL };
	HOOK_TRACE_INFO hHookGetClipboardData = { NULL };
	HOOK_TRACE_INFO hHookmyGetComputerNameW = { NULL };
	HOOK_TRACE_INFO hHookGetVersionExA = { NULL };
	HOOK_TRACE_INFO hHookSend = { NULL };
	HOOK_TRACE_INFO hHookShellExecuteExW = { NULL };
	HOOK_TRACE_INFO hHookWriteFile = { NULL };

	//std::cout << "\n";
	//std::cout << "Win32 Beep found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep") << "\n";
	//std::cout << "Win32 GetCurrentDirectoryW found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetCurrentDirectoryW") << "\n";
	//std::cout << "Win32 ReadFile found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "ReadFile") << "\n";
	//std::cout << "Win32 CreateFileW found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileW") << "\n";
	//std::cout << "Win32 CreateProcessW found at address: " << GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateProcessW") << "\n";

	// Install the hook

	Config config;
	loadConfig(config);
	cout << config.Behave << '\n';
	cout << config.HoneyServer << '\n';
	cout << config.Strat << '\n';

	Behave = config.Behave;
	HoneyServer = config.HoneyServer;
	DECEPTION_STRAT = config.Strat;

	if (Behave == 1) {
		NTSTATUS resultGetClipboardData = LhInstallHook(
			GetProcAddress(GetModuleHandle(TEXT("user32")), "GetClipboardData"),
			myGetClipboardData,
			NULL,
			&hHookGetClipboardData);
	}
	if (Behave == 2) {
		NTSTATUS resultSend = LhInstallHook(
			GetProcAddress(GetModuleHandle(TEXT("ws2_32")), "send"),
			mySend,
			NULL,
			&hHookSend);

		NTSTATUS resultGetShellExecuteExW = LhInstallHook(
			GetProcAddress(GetModuleHandle(TEXT("shell32")), "ShellExecuteExW"),
			myShellExecuteExW,
			NULL,
			&hHookShellExecuteExW);

		NTSTATUS resultGetWriteFile = LhInstallHook(
			GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile"),
			myWriteFile,
			NULL,
			&hHookWriteFile);

		NTSTATUS result = LhInstallHook(
			GetProcAddress(GetModuleHandle(TEXT("kernel32")), "Beep"),
			myBeepHook,
			NULL,
			&hHook);

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
	}

	
	
	/*
	NTSTATUS resultGetComputerNameW = LhInstallHook(
	GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetComputerNameExW"),
	myGetComputerNameW,
	NULL,
	&hHookmyGetComputerNameW);
	*/
	if(Behave == 3){
		NTSTATUS resultGetVersionExA = LhInstallHook(
			GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetVersionExA"),
			myGetVersionExA,
			NULL,
			&hHookGetVersionExA);
	}
	if (Behave == 6) {
		NTSTATUS resultGetCurrentDirectoryW = LhInstallHook(
			GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetCurrentDirectoryW"),
			myGetCurrentDirectoryW,
			NULL,
			&hHookGetCurrentDirectoryW);
	}
	


	// && FAILED(resultSend)&& FAILED(resultGetClipboardData) && FAILED(resultCreatePipe) && FAILED(resultCreateProcessW) && FAILED(resultCreateFileW) && FAILED(resultReadFile) && FAILED(resultGetCurrentDirectoryW) && FAILED(resultGetWriteFile)
	/*
	if (FAILED(resultSend) && FAILED(resultGetClipboardData) && FAILED(resultCreatePipe) && FAILED(resultCreateProcessW) && FAILED(resultCreateFileW) && FAILED(resultReadFile) && FAILED(resultGetCurrentDirectoryW) && FAILED(resultGetWriteFile) && FAILED(resultGetShellExecuteExW) && FAILED(resultGetWriteFile) && FAILED(result))
	{
		std::wstring s(RtlGetLastErrorString());
		std::wcout << "Failed to install hook: ";
		std::wcout << s;
	}
	else
	{
		std::cout << "Hook 'myBeepHook installed successfully.\n";
	}*/

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	std::cout << "****Hooked****\n";
	if (Behave == 1) {
		LhSetExclusiveACL(ACLEntries, 1, &hHookGetClipboardData);
	}
	if (Behave == 2) {
		LhSetExclusiveACL(ACLEntries, 1, &hHookSend);
		LhSetExclusiveACL(ACLEntries, 1, &hHookWriteFile);
		LhSetExclusiveACL(ACLEntries, 1, &hHookShellExecuteExW);
		LhSetExclusiveACL(ACLEntries, 1, &hHookmyGetComputerNameW);
		LhSetExclusiveACL(ACLEntries, 1, &hHook);
		LhSetExclusiveACL(ACLEntries, 1, &hHookReadFile);
		LhSetExclusiveACL(ACLEntries, 1, &hHookCreateFileW);
		LhSetExclusiveACL(ACLEntries, 1, &hHookCreateProcessW);
		LhSetExclusiveACL(ACLEntries, 1, &hHookDuplicateHandle);
		LhSetExclusiveACL(ACLEntries, 1, &hHookCreatePipe);
	}
	if (Behave == 3) {
		LhSetExclusiveACL(ACLEntries, 1, &hHookGetVersionExA);
	}
	if (Behave == 6) {
		LhSetExclusiveACL(ACLEntries, 1, &hHookGetCurrentDirectoryW);
	}

	return;
}