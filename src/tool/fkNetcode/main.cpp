#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinInet.h>
#include <winsock.h>
#include "fkConfig.h"
#include "fkPatch.h"
#include "fkUtils.h"
#include "PEInfo.h"

#include <fstream>

// ---- Configuration ----

CHAR cfgFallbackIP[16];
CHAR cfgServiceUrl[MAX_PATH];
BOOL cfgShowErrors;

// ---- Patch: IP Resolval ----

CHAR cachedIP[16] = {};

void configure();

struct ThreadData {
	HANDLE directoryHandle;
	const wchar_t* directoryPath;
	const wchar_t* targetFileName;
};

void MonitorDirectoryThread(void* data) {
	struct ThreadData* threadData = (struct ThreadData*)data;
	HANDLE directoryHandle = threadData->directoryHandle;
	const wchar_t* directoryPath = threadData->directoryPath;
	const wchar_t* targetFileName = threadData->targetFileName;

	// Buffer to store the changes
	const int bufferSize = 4096;
	BYTE buffer[4096];

	DWORD bytesRead;
	FILE_NOTIFY_INFORMATION* fileInfo;

	while (ReadDirectoryChangesW(
		directoryHandle,
		buffer,
		bufferSize,
		FALSE, // Ignore subtree
		FILE_NOTIFY_CHANGE_LAST_WRITE, // Monitor file write changes
		&bytesRead,
		NULL,
		NULL
	)) {
		fileInfo = (FILE_NOTIFY_INFORMATION*)buffer;

		//Make sure that the file that got written to is the file we are monitoring
		if (wcsncmp(fileInfo->FileName, targetFileName, fileInfo->FileNameLength / sizeof(wchar_t)) != 0)
			continue;

		do {

			switch (fileInfo->Action) {
			case FILE_ACTION_MODIFIED:
				configure();
				break;
			default:
				break;
			}

			// Move to the next entry in the buffer
			fileInfo = (FILE_NOTIFY_INFORMATION*)((char*)fileInfo + fileInfo->NextEntryOffset);

		} while (fileInfo->NextEntryOffset != 0);
	}

	// Close the directory handle when the monitoring loop exits
	CloseHandle(directoryHandle);
}

void MonitorDirectory(const wchar_t* directoryPath, const wchar_t* targetFileName)
{
	// Create a directory handle
	HANDLE directoryHandle = CreateFileW(
		directoryPath,
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		NULL
	);

	if (directoryHandle == INVALID_HANDLE_VALUE) {
		wprintf(L"Error opening directory: %d\n", GetLastError());
		return;
	}

	// Prepare data to pass to the thread
	struct ThreadData* threadData = (struct ThreadData*)malloc(sizeof(struct ThreadData));
	if (threadData == NULL) {
		wprintf(L"Memory allocation failed\n");
		CloseHandle(directoryHandle);
		return;
	}
	threadData->directoryHandle = directoryHandle;
	threadData->directoryPath = directoryPath;
	threadData->targetFileName = targetFileName;

	// Create a thread for monitoring
	HANDLE threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorDirectoryThread, threadData, 0, NULL);

	//Closes the handle to the thread, however this does not stop the thread
	CloseHandle(threadHandle);
}

inline bool fileExists(const std::string& name) {
	std::ifstream file(name);
	return file.good();
}

void configure()
{
	if (cachedIP[0]) {
		cachedIP[0] = NULL;
	}

	fk::Config config("fkNetcode.ini");

	// Load INI settings.
	config.get("AddressResolval", "FallbackIP", cfgFallbackIP, 16);
	config.get("AddressResolval", "ServiceUrl", cfgServiceUrl, MAX_PATH, "http://ip.syroot.com");
	config.get("AddressResolval", "ShowErrors", cfgShowErrors, TRUE);

	// Ensure INI file has been created with default setting.
	bool exists = fileExists("fkNetcode.ini");

	if (!exists)
	{
		config.set("AddressResolval", "FallbackIP", cfgFallbackIP);
		config.set("AddressResolval", "ServiceUrl", cfgServiceUrl);
		config.set("AddressResolval", "ShowErrors", cfgShowErrors);
	}

	// Validate fallback IP.
	BYTE b;
	if (*cfgFallbackIP && sscanf_s(cfgFallbackIP, "%hhu.%hhu.%hhu.%hhu", &b, &b, &b, &b) != 4)
	{
		*cfgFallbackIP = NULL;
		MessageBox(NULL, "Invalid fallback IP setting in fkNetcode.ini has been ignored.", "fkNetcode", MB_ICONWARNING);
	}
}

bool resolveIPCached(LPSTR buffer)
{
	if (!*cachedIP)
		return false;
	lstrcpy(buffer, cachedIP);
	return true;
}

bool resolveIPExternal(LPSTR buffer)
{
	if (!*cfgServiceUrl)
		return false;

	// Query a web service which replies with the IP in plain text.
	HINTERNET hInternet = 0, hFile = 0;
	if (hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0))
	{
		if (hFile = InternetOpenUrl(hInternet, cfgServiceUrl, NULL, 0,
			INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, NULL))
		{
			DWORD responseLength = 0;
			CHAR response[16];
			if (InternetReadFile(hFile, response, sizeof(response) -1, &responseLength))
			{
				if (responseLength >= 7)
				{
					response[responseLength] = '\0';
					BYTE temp;
					if (sscanf_s(response, "%hhu.%hhu.%hhu.%hhu", &temp, &temp, &temp, &temp) == 4)
						lstrcpy(buffer, response);
					else
						SetLastError(0x20000002);
				}
				else
				{
					SetLastError(0x20000001);
				}
			}
		}
	}

	DWORD error = GetLastError();
	if (hFile) InternetCloseHandle(hFile);
	if (hInternet) InternetCloseHandle(hInternet);
	if (error && cfgShowErrors)
	{
		CHAR msg[512];
		sprintf_s(msg, "Could not resolve your IP through the web service. %s", fk::getErrorMessage(error).c_str());
		MessageBox(NULL, msg, "fkNetcode", MB_ICONWARNING);
	}
	return !error;
}

bool resolveIPFallback(LPSTR buffer)
{
	if (!*cfgFallbackIP)
		return false;
	lstrcpy(buffer, cfgFallbackIP);
	return true;
}

bool resolveIPOriginal(LPSTR buffer)
{
	// Use the original logic to "resolve" the (NAT) IP.
	CHAR hostName[200];
	hostent* host;
	if (gethostname(hostName, 200) || !(host = gethostbyname(hostName)))
		return false;

	sprintf_s(hostName, "%hhu.%hhu.%hhu.%hhu",
		host->h_addr_list[0][0],
		host->h_addr_list[0][1],
		host->h_addr_list[0][2],
		host->h_addr_list[0][3]);
	lstrcpy(buffer, hostName);
	return true;
}

bool __stdcall patchResolveIP(LPSTR buffer, int bufferLength)
{
	// Return value not used by W2, but meant to be 0 if no error.
	if (resolveIPCached(buffer) || resolveIPExternal(buffer) || resolveIPFallback(buffer) || resolveIPOriginal(buffer))
	{
		lstrcpy(cachedIP, buffer);
		return false;
	}
	else
	{
		return true;
	}
}

// ---- Patch ----

void patch(PEInfo& pe, int gameVersion)
{
	fk::Patch::jump(pe.Offset(0x00001799), 5, &patchResolveIP, fk::IJ_JUMP); // replace IP resolve with web service

	if (gameVersion == fk::GAME_VERSION_TRY)
	{
		fk::Patch::nops(pe.Offset(0x00053B96), 5); // prevent overriding IP with user name
		fk::Patch::nops(pe.Offset(0x00054693), 5); // prevent overriding IP with NAT IP
		fk::Patch::nops(pe.Offset(0x00054635), 11); // useless sleep when connecting to server
	}
	else
	{
		fk::Patch::nops(pe.Offset(0x00053E96), 5); // prevent overriding IP with user name
		fk::Patch::nops(pe.Offset(0x00054935), 11); // useless sleep when connecting to server
		fk::Patch::nops(pe.Offset(0x00054993), 5); // prevent overriding IP with NAT IP
	}
}

// ---- Main ----

BOOL WINAPI DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			PEInfo pe;
			int tds = pe.FH->TimeDateStamp;
			int version = fk::getGameVersion(tds);
			if (version == fk::GAME_VERSION_NONE){
				MessageBox(NULL, "fkNetcode is incompatible with your game version. Please run the 1.05 patch or 1.07 "
					"release of Worms 2. Otherwise, you can delete the module to remove this warning.", "fkNetcode",
					MB_ICONWARNING);
			}
			else
			{
				configure();
				patch(pe, version);

				//Gets the current working directory, and creates a path containing it and the fkNetcode.ini file that we want to monitor for changes
				wchar_t directoryPath[1024];
				_wgetcwd(directoryPath, sizeof(directoryPath) / sizeof(directoryPath[0]));
				const wchar_t* targetFileName = L"fkNetcode.ini";
				MonitorDirectory(directoryPath, targetFileName);
			}
		}
		break;
	
		case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
