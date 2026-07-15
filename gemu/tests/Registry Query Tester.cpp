#include <windows.h>
#include <stdlib.h>
#include <iostream>
#include <codecvt>
#include <locale>

// - Test Code - 

void test01W(const wchar_t* key, const std::wstring& subkey, const std::wstring& defaultValue) {
	//std::wcout << L"[Test 01W] Suche Wert fuer: \"" << key << "\"\t\"" << subkey<< "\"" << std::endl;
	//gemu_log("OOOOO__Start_Test01W");
	HKEY hKey;
	LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, (LPCWSTR)key, 0, KEY_READ, &hKey);

	std::wstring strValue;

	strValue = defaultValue;
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;

	nError = RegQueryValueExW(hKey, subkey.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);

	if (nError != ERROR_SUCCESS)
		std::cout << "\t======== Fehler: < " << nError << " >" << std::endl;
	else {
		strValue = szBuffer;
		std::wcout << L"\t\t-> Gefundener Wert: \"" << strValue << "\"" << std::endl;
	}

	RegCloseKey(hKey);

	return;
}

void test01A(const char* key, const std::string& subkey, const std::string& defaultValue) {
	//std::cout << "[Test 01A] Suche Wert fuer: \"" << key << "\"\t\"" << subkey << "\"" << std::endl;
	//gemu_log("OOOOO__Start_Test01A");
	HKEY hKey;
	LONG lRes = RegOpenKeyExA(HKEY_LOCAL_MACHINE, (LPCSTR)key, 0, KEY_READ, &hKey);

	std::string strValue;

	strValue = defaultValue;
	CHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;

	nError = RegQueryValueExA(hKey, subkey.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);

	if (nError != ERROR_SUCCESS)
		std::cout << "\t======== Fehler: < " << nError << " >" << std::endl;
	else {
		strValue = szBuffer;
		std::cout << "\t\t-> Gefundener Wert: \"" << strValue << "\"" << std::endl;
	}

	RegCloseKey(hKey);

	return;
}

void test01(const wchar_t* key, const std::wstring& subkey, const std::wstring& defaultValue) {
	test01W(key, subkey, defaultValue);

	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	char keyString[512];
	size_t number = 0;
	wcstombs_s(&number, keyString, 512, key, 1024);

	test01A(keyString, converter.to_bytes(subkey), converter.to_bytes(defaultValue));
}

// - Test Cases - 

int main()
{
	test01(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesDir", L"unknown");    //REG_SZ
	test01(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", L"ProgramFilesPath", L"unknown");	//REG_EXPAND_SZ	
	test01(L"SYSTEM\\RNG", L"Seed", L"unknown"); //REG_BINARY
	test01(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate", L"unknown"); // REG_DWORD
	test01(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallTime", L"unknown"); // REG_QWORD
	test01(L"HARDWARE\\DESCRIPTION\\System", L"SystemBiosVersion", L"unknown"); // REG_MULTI_SZ with (probably) one entry
	test01(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", L"LocalService", L"unknown"); // REG_MULTI_SZ with (probably) several entries
}
