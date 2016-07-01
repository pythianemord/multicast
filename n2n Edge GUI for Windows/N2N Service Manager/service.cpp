/*
  N2N Service Manager - Utility to run n2n applications as a service
  Copyright (C) 2010  Ryan M. Dorn
  https://sourceforge.net/projects/n2nedgegui/
  $Id: service.cpp 2 2010-03-25 23:47:47Z Ryand833 $

  This file is part of N2N Edge GUI.

  N2N Service Manager is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  N2N Service Manager is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with N2N Service Manager.  If not, see <http://www.gnu.org/licenses/>.
  ---------------------------------------------------------------
  Code based on NSSM - the Non-Sucking Service Manager
  Copyright (C) 2010 Iain Patterson
  http://tterson.net/src/nssm
*/

#include "stdafx.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <io.h>
#include "Shlwapi.h"
#include <stdio.h>
#include "service.h"
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include "shellapi.h"
#include <windows.h>
#include <stdexcept>

#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams
using namespace std;

SERVICE_STATUS srv_status;
SERVICE_STATUS_HANDLE srv_handle;
HANDLE wait_handle;
HANDLE pid;
WCHAR exe_path[MAX_PATH];
WCHAR command_line[1024];
bool start_supernode = false;
std::wstring ip;

PIP_ADAPTER_ADDRESSES pAddresses = NULL;
PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
ULONG outBufLen = 0;
ULONG family = AF_INET;
ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
DWORD dwRetVal = 0;
WCHAR mapping_file_path[512];

int retrieve_ip_mapping_file(WCHAR* url) {
	auto fileStream = std::make_shared<Concurrency::streams::ostream>();
	try
	{
		// Open stream to output file.
		pplx::task<void> requestTask = Concurrency::streams::fstream::open_ostream(mapping_file_path).then([=](Concurrency::streams::ostream outFile)
		{
			*fileStream = outFile;

			// Create http_client to send the request.
			http_client client(url);
			return client.request(methods::GET);
		})

			// Handle response headers arriving.
			.then([=](http_response response)
		{
			//printf("Received response status code:%u\n", response.status_code());
			if (response.status_code() != 200) {
				CHAR tempError[40];
				sprintf_s(tempError, _countof(tempError), "Invalid HTTP response code: %d", response.status_code());
				throw std::exception(tempError);
			}
			// Write response body into the file.
			return response.body().read_to_end(fileStream->streambuf());
		})

			// Close the file stream.
			.then([=](size_t)
		{
			return fileStream->close();
		});

		// Wait for all the outstanding I/O to complete and handle any exceptions

		requestTask.wait();
	}
	catch (const std::exception &e)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Error retrieving mapping file via HTTP: %hs.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__), e.what());
		return 1;
	}

	return 0;


}


void log_event(unsigned short type, WCHAR* format, ...)
{
	WCHAR message[4096];
	WCHAR* strings[2];
	int n, size;
	va_list arg;

	// Construct the message
	size = _countof(message);
	va_start(arg, format);
	n = _vsnwprintf_s(message, size, _TRUNCATE, format, arg);
	va_end(arg);

	// Check success
	if (n < 0 || n >= size) return;

	// Construct strings array
	strings[0] = message;
	strings[1] = 0;

	// Open event log
	HANDLE handle = RegisterEventSource(0, L"n2n_srv");
	if (!handle) return;

	// Log the message
	if (!ReportEvent(handle, type, 0, 0, 0, 1, 0, (const WCHAR**)strings, 0))
	{
		wprintf_s(L"%s:%d (%s) - ReportEvent() failed.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
	}

	// Close event log
	DeregisterEventSource(handle);
}

int build_exe_path(WCHAR* exe_path, int buf_len)
{
	DWORD exe_buf_len = buf_len * sizeof(WCHAR);

	// Open registry key
	HKEY hkey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\N2N Edge GUI", NULL, KEY_READ, &hkey) != ERROR_SUCCESS)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Error opening registry key.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return 0;
	}

	// Get executable path
	if (RegQueryValueEx(hkey, L"Path", NULL, NULL, (LPBYTE)exe_path, &exe_buf_len) != ERROR_SUCCESS)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Unable to read 'Path' registry value.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		RegCloseKey(hkey);
		return 0;
	}
	RegCloseKey(hkey);
	return 1;
}


std::wstring get_ip_from_mapping_file() {
	try {
		#define INFO_BUFFER_SIZE 32767
		TCHAR  infoBuf[INFO_BUFFER_SIZE];
		DWORD  bufCharCount = INFO_BUFFER_SIZE;

		//Get the computer name and convert it into something that's easy to compare
		bufCharCount = INFO_BUFFER_SIZE;
		GetComputerName(infoBuf, &bufCharCount);
		for (DWORD i = 0; i < bufCharCount; i++) {
			infoBuf[i] = tolower(infoBuf[i]);
		}
		std::wstring hostname = infoBuf;


		std::wstring line;
		int comma;
		std::wstring host;
		std::wstring ip;
		std::wfstream dataFile(mapping_file_path, ios::in);
		if (dataFile.is_open())
		{
			while (dataFile.good()) {

				std::getline(dataFile, line);

				//Ignore commented lines
				if (line[0] == '#')
					continue;

				//Split the line on the comma. If it doesn't exist, ignore the line
				comma = line.find(',');
				if (comma == string::npos)
					continue;
				host = line.substr(0, comma);
				ip = line.substr(comma + 1, line.length() - comma - 1);

				//Convert the hostname to lowercase for comparison
				for (u_int i = 0; i < host.length(); i++) {
					host[i] = tolower(host[i]);
				}

				//Compare the host from the line to the actual hostname. If it's a match, return the IP.
				if (hostname.compare(host) == 0) {
					dataFile.close();
					return ip;
				}
			}
		}
		dataFile.close();
	}
	catch (const std::exception &e)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Error reading mapping file: %hs\n", _T(__FILE__), __LINE__, _T(__FUNCTION__), e.what());
	}
	//We didn't find a match in the file.
	return L"NOMATCH";
}


int build_command_line_edge(WCHAR* exe_path, WCHAR* command_line, int buf_len)
{
	command_line[0] = 0;
	WCHAR ret_val[512];
	DWORD ret_dword = 0;



	// Use 'ptr' to append to the end of the command line
	WCHAR* ptr = command_line;
	ptr += swprintf_s(command_line, buf_len, L"\"%s\\edge.exe\"", exe_path);

	// Open registry key
	HKEY hkey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\N2N Edge GUI\\Parameters", NULL, KEY_READ, &hkey) != ERROR_SUCCESS)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Error opening registry key.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return 0;
	}

	// Community
	if (!reg_get_string(hkey, L"community", ret_val, 512)) return 0;
	ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -c %s", ret_val);

	// Encryption key
	if (!reg_get_string(hkey, L"enckey", ret_val, 512)) return 0;
	if (wcslen(ret_val) != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -k %s", ret_val);
	}


	// Mapping URL
	if (!reg_get_string(hkey, L"mapping_url", ret_val, 512)) return 0;

	if (!reg_get_string(hkey, L"mapping_file_path", mapping_file_path, 512)) return 0;

	//Attempt to retrieve the latest version of the mapping file
	int http_ret = retrieve_ip_mapping_file(ret_val);

	//If the file doesn't exist, we can't assign the IP so we must quit
	if (_waccess(mapping_file_path, 0) == -1) {
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Unable to find mapping file.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return 0;
	}

	//Get the IP and exit if there was no match
	ip = get_ip_from_mapping_file();
	if (ip.compare(L"NOMATCH") == 0) {
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Unable to find matching hostname.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return 0;
	}

	/*
	// IP address
	if (!reg_get_string(hkey, L"ip_address", ret_val, 512)) return 0;
	if (wcslen(ret_val) != 0)
	{
	  ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -a %s", ret_val);
	}
	else
	{
	  ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -a dhcp:0.0.0.0");
	}
	*/
	ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -a %s", ip.c_str());

	// Encryption key file
	if (!reg_get_string(hkey, L"keyfile", ret_val, 512)) return 0;
	if (wcslen(ret_val) != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -K %s", ret_val);
	}

	// Local Port
	if (!reg_get_dword(hkey, L"local_port", &ret_dword)) return 0;
	if (ret_dword != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -p %d", ret_dword);
	}

	//00:FF:1F:EE:A2:XX
	// MAC address
	/*
	if (!reg_get_string(hkey, L"mac_address", ret_val, 512)) return 0;
	if (wcslen(ret_val) != 0)
	{
	  ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -m %s", ret_val);
	}*/

	ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -m 00:FF:1F:EE:A2:%02X", stoi(ip.substr(ip.rfind('.') + 1, ip.length() - ip.rfind('.'))));


	// MTU
	if (!reg_get_dword(hkey, L"mtu", &ret_dword)) return 0;
	if (ret_dword != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -M %d", ret_dword);
	}

	// Multicast
	if (!reg_get_dword(hkey, L"multicast", &ret_dword)) return 0;
	if (ret_dword != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -E");
	}

	// Packet forwarding
	if (!reg_get_dword(hkey, L"packet_forwarding", &ret_dword)) return 0;
	if (ret_dword != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -r");
	}

	// Resolve supernode IP
	if (!reg_get_dword(hkey, L"resolve_ip", &ret_dword)) return 0;
	if (ret_dword != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -b");
	}

	// Subnet mask
	if (!reg_get_string(hkey, L"subnet_mask", ret_val, 512)) return 0;
	if (wcslen(ret_val) != 0)
	{
		ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -s %s", ret_val);
	}
	// Supernode address
	if (!reg_get_string(hkey, L"supernode_addr", ret_val, 512)) return 0;
	ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -l %s", ret_val);

	// Supernode port
	if (!reg_get_dword(hkey, L"supernode_port", &ret_dword)) return 0;
	ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L":%d", ret_dword);

	return 1;
}

int build_command_line_supernode(WCHAR* exe_path, WCHAR* command_line, int buf_len)
{
	command_line[0] = 0;
	DWORD ret_dword = 0;

	// Use 'ptr' to append to the end of the command line
	WCHAR* ptr = command_line;
	ptr += swprintf_s(command_line, buf_len, L"\"%s\\supernode.exe\"", exe_path);

	// Open registry key
	HKEY hkey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\N2N Edge GUI\\Parameters", NULL, KEY_READ, &hkey) != ERROR_SUCCESS)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Error opening registry key.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return 0;
	}

	// Supernode server port
	if (!reg_get_dword(hkey, L"supernode_server_port", &ret_dword)) return 0;
	ptr += swprintf_s(ptr, buf_len - (ptr - command_line), L" -l %d", ret_dword);

	return 1;
}

int reg_get_dword(HKEY hkey, LPWSTR value_name, LPDWORD ret_dword)
{
	// Fetch DWORD value from registry
	DWORD buf_size = sizeof(DWORD);
	if (RegQueryValueEx(hkey, value_name, NULL, NULL, (LPBYTE)ret_dword, &buf_size) != ERROR_SUCCESS)
	{
		*ret_dword = 0;
		return 0;
	}
	return 1;
}

int reg_get_string(HKEY hkey, LPWSTR value_name, LPWSTR ret_str, DWORD buf_size)
{
	// Fetch string value from registry
	if (RegQueryValueEx(hkey, value_name, NULL, NULL, (LPBYTE)ret_str, &buf_size) != ERROR_SUCCESS)
	{
		return 0;
	}
	return 1;
}

int start_service()
{
	if (pid) return 0;

	// Allocate a STARTUPINFO structure for a new process
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFO);

	// Allocate a PROCESSINFO structure for the process
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	// Launch executable
	if (!CreateProcess(NULL, command_line, NULL, NULL, NULL, NULL, NULL, exe_path, &si, &pi))
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Unable to launch supernode process.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return stop_service(3);
	}
	pid = pi.hProcess;

	// Signal successful start
	srv_status.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(srv_handle, &srv_status);


	outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
	std::wstring intIP;

	unsigned int count = 0;
	unsigned int i = 0;
	boolean interfaceOperational = false;
	ULONG iterations;

	//Need to find the interface with the specified IP address and make sure it's operational before we try to add routes that use it
	while (!interfaceOperational) {

		iterations = 0;
		do {
			
			pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
			if (pAddresses == NULL) {
				exit(1);
			}
			
			//Grab the interface IPs
			dwRetVal =
				GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

			if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
				FREE(pAddresses);
				pAddresses = NULL;
			}
			else {
				break;
			}

			iterations++;

		} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < 3));


		if (dwRetVal == NO_ERROR) {
			pCurrAddresses = pAddresses;
			while (pCurrAddresses) {
				pUnicast = pCurrAddresses->FirstUnicastAddress;
				if (pUnicast != NULL) {
					for (i = 0; pUnicast != NULL; i++) {
						//Originally used WSAAddressToString but the Winsock libraries didn't seem to update correctly if used on boot.
						//So now we manually convert it from the sockaddr struct
						sockaddr_in* address = (sockaddr_in*)pUnicast->Address.lpSockaddr;
						intIP = std::to_wstring(address->sin_addr.S_un.S_un_b.s_b1) +
							L'.' +
							std::to_wstring(address->sin_addr.S_un.S_un_b.s_b2) +
							L'.' +
							std::to_wstring(address->sin_addr.S_un.S_un_b.s_b3) +
							L'.' +
							std::to_wstring(address->sin_addr.S_un.S_un_b.s_b4);
						//If the IP matches and the interface is fully operational, we're good to go
						if (ip.compare(intIP) == 0 && pCurrAddresses->OperStatus == 1) {
							interfaceOperational = true;
							break;
						}
						pUnicast = pUnicast->Next;
					}
				}
				pCurrAddresses = pCurrAddresses->Next;
			}
		}
		if (count > 60) {
			return 1;
		}
		count++;
		if (pAddresses) {
			FREE(pAddresses);
		}
		pCurrAddresses = NULL;
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	//Give it a little extra time before trying to add the routes
	std::this_thread::sleep_for(std::chrono::milliseconds(3000));

	std::wstring routeStrings[]{
		L"add 230.0.0.1 mask 255.255.255.255 %s",
		L"add 239.0.0.1 mask 255.255.255.255 %s"
	};


	int size;
	std::wstring wMessage;

	//Add static routes to the edge interface to encourage the app to use the edge interface for multicast messages
	for (int i = 0; i < _countof(routeStrings); i++) {
		WCHAR message[4096];
		size = _countof(message);
		swprintf(message, size, routeStrings[i].c_str(), ip.c_str());

		wMessage = message;

		ShellExecuteW(NULL, L"open",
			L"route.exe",
			wMessage.c_str(),
			NULL, SW_HIDE);
	}
	return 0;
}


int stop_service(unsigned long exitcode)
{
	// Signal we are stopping
	srv_status.dwCurrentState = SERVICE_STOP_PENDING;
	SetServiceStatus(srv_handle, &srv_status);

	// Do nothing if the server isn't running
	if (pid)
	{
		TerminateProcess(pid, 0);
		pid = 0;
	}

	// Signal we stopped
	srv_status.dwCurrentState = SERVICE_STOPPED;
	if (exitcode)
	{
		srv_status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		srv_status.dwServiceSpecificExitCode = exitcode;
	}
	else
	{
		srv_status.dwWin32ExitCode = NO_ERROR;
		srv_status.dwServiceSpecificExitCode = 0;
	}
	SetServiceStatus(srv_handle, &srv_status);

	std::wstring routeStrings[]{
		L"delete 230.0.0.1 mask 255.255.255.255 %s",
		L"delete 239.0.0.1 mask 255.255.255.255 %s"
	};



	int size;
	std::wstring wMessage;

	for (int i = 0; i < _countof(routeStrings); i++) {
		WCHAR message[4096];
		size = _countof(message);
		swprintf(message, size, routeStrings[i].c_str(), ip.c_str());

		wMessage = message;

		ShellExecuteW(NULL, L"open",
			L"route.exe",
			wMessage.c_str(),
			NULL, SW_HIDE);
	}


	return exitcode;
}

VOID CALLBACK end_service(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
	// check exit code
	unsigned long ret = 0;
	GetExitCodeProcess(pid, &ret);

	pid = 0;

	log_event(EVENTLOG_INFORMATION_TYPE, L"%s:%d (%s) - Process exited with return code %u.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__), ret);

	// Wait 5 seconds, then restart process
	Sleep(5000);
	while (monitor_service())
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Failed to restart service.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		Sleep(30000);
	}
}

int monitor_service()
{
	// Set service status to started
	int ret = start_service();
	if (ret)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Unable to start service.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return ret;
	}
	// Monitor service
	if (!RegisterWaitForSingleObject(&wait_handle, pid, end_service, 0, INFINITE, WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION))
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Unable to call RegisterWaitForSingleObject.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
	}
	return 0;
}

DWORD WINAPI service_ctrl_handler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		stop_service(0);
		return NO_ERROR;
	}
	return ERROR_CALL_NOT_IMPLEMENTED;
}

void killService() {
	if (pid)
	{
		TerminateProcess(pid, 0);
		pid = 0;
	}
	SERVICE_STATUS k_Status = { 0 };
	k_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	k_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	k_Status.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(srv_handle, &k_Status);

	ExitProcess(0);
}

VOID WINAPI service_main(DWORD dwNumServiceArgs, LPWSTR *lpServiceArgVectors)
{
	ZeroMemory(&srv_status, sizeof(SERVICE_STATUS));
	srv_status.dwCheckPoint = 0;
	srv_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	srv_status.dwCurrentState = SERVICE_RUNNING;
	srv_status.dwServiceSpecificExitCode = 0;
	srv_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	srv_status.dwWaitHint = 1000;
	srv_status.dwWin32ExitCode = NO_ERROR;


	// Build path and command line parameters
	if (!build_exe_path(exe_path, MAX_PATH))
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Error building executable path.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		return;
	}
	int ret = 0;
	if (start_supernode)
	{
		ret = build_command_line_supernode(exe_path, command_line, 1024);
	}
	else
	{
		ret = build_command_line_edge(exe_path, command_line, 1024);
	}
	if (!ret)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Error building command line.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		killService();
		return;
	}
	srv_handle = RegisterServiceCtrlHandlerEx(L"n2n_srv", service_ctrl_handler, 0);
	if (!srv_handle)
	{
		log_event(EVENTLOG_ERROR_TYPE, L"%s:%d (%s) - Unable to register service control handler.\n", _T(__FILE__), __LINE__, _T(__FUNCTION__));
		killService();
		return;
	}

	pid = NULL;
	if (monitor_service() != 0) {
		// Inform the Service Control Manager that the service is stopped now.
		killService();
	}
}

