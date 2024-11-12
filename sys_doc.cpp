// g++ -I "C:\Program Files\OpenSSL-Win64\include" -L "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MDd" .\sys_doc.cpp -o .\sys_doc.exe "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MDd\libcrypto.lib" 
// "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MDd\libssl.lib"
#define UNICODE
#include <AclAPI.h>
#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <shlobj.h>
#include <sstream>
#include <iomanip>
#include <winbase.h>
#include <thread>
#include <chrono>
#include <openssl/sha.h>

using namespace std;

// Функция для получения информации о системе
string GetSystemInfo() {
    stringstream sysInfo;
    char userName[256];
    DWORD userNameSize = sizeof(userName);
    GetUserNameA(userName, &userNameSize);
    sysInfo << "Name of the user: " << userName << endl;

    char computerName[256];
    DWORD computerNameSize = sizeof(computerName);
    GetComputerNameA(computerName, &computerNameSize);
    sysInfo << "Processor name: " << computerName << endl;

    SYSTEM_INFO sysInfoStruct;
    GetSystemInfo(&sysInfoStruct);
    sysInfo << "Processor: " << sysInfoStruct.dwProcessorType << endl;

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    sysInfo << "Memory: " << memStatus.ullTotalPhys / (1024 * 1024) << " MB" << endl;

    OSVERSIONINFOEX osVer;
    osVer.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFO)&osVer);
    sysInfo << "OS: Windows " << osVer.dwMajorVersion << "." << osVer.dwMinorVersion << endl;

    return sysInfo.str();
}

// Функция для кодирования информации (SHA-256)
string EncodeInformation(const string& info) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // Выполняем хеширование с помощью OpenSSL SHA256
    SHA256(reinterpret_cast<const unsigned char*>(info.c_str()), info.size(), hash);

    // Конвертируем результат в шестнадцатеричную строку
    stringstream encoded;
    encoded << hex << setw(2) << setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        encoded << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return encoded.str();
}

void DenyReadAccess(const string& filePath) {
    // Получаем текущее описание безопасности файла
    PSECURITY_DESCRIPTOR pSD = NULL;
    GetFileSecurityA(filePath.c_str(), DACL_SECURITY_INFORMATION, pSD, 0, NULL);

    // Создаем ACL, которая будет запрещать доступ
    PACL pDACL = NULL;
    EXPLICIT_ACCESS ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));

    ea.grfAccessPermissions = GENERIC_READ;  // Запрещаем чтение
    ea.grfAccessMode = DENY_ACCESS;  // Запрещаем доступ
    ea.grfInheritance = NO_INHERITANCE;

    wstring wideTrusteeName = L"Everyone";
    wchar_t* trusteeName = new wchar_t[wideTrusteeName.length() + 1];
    wcscpy_s(trusteeName, wideTrusteeName.length() + 1, wideTrusteeName.c_str());

    BuildExplicitAccessWithName(&ea, trusteeName, ea.grfAccessPermissions, ea.grfAccessMode, ea.grfInheritance);

    SetEntriesInAcl(1, &ea, pDACL, &pDACL);

    SetFileSecurityA(filePath.c_str(), DACL_SECURITY_INFORMATION, pSD);

    delete[] trusteeName;
}

void WriteSysTat(const string& filePath, const string& info) {
    ofstream file(filePath);
    file << info;
    file.close();

    // Делаем файл доступным только для записи (без чтения)
    SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);

    // Запрещаем чтение файла
    DenyReadAccess(filePath);
}

// Функция для записи подписи в реестр
void SaveSignatureToRegistry(const string& signature) {
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Mikhailik"), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, TEXT("Signature"), 0, REG_SZ, (const BYTE*)signature.c_str(), signature.size() + 1);
        RegCloseKey(hKey);
    }
}

void showProgress(int totalSteps) {
    for (int i = 0; i <= totalSteps; i++) {
        // Рассчитываем процент завершенности
        float progress = (float)i / totalSteps * 100;

        // Выводим строку прогресса
        cout << "\r[";
        int pos = i * 50 / totalSteps; // 50 — длина прогресс-бара
        for (int j = 0; j < 50; j++) {
            if (j < pos) {
                cout << "#"; // Заполнение прогресса
            } else {
                cout << " "; // Пустое место
            }
        }
        cout << "] " << int(progress) << "%";

        // Ожидаем 100 мс для имитации работы
        this_thread::sleep_for(chrono::milliseconds(100));
    }
    cout << endl; // Переводим на новую строку после завершения прогресса
}

int main() {

    string installPath;
    wstring wideInstallPath;
    cout << "Enter the path to install \"Paint\" update: ";
    getline(cin, installPath);

    wideInstallPath = wstring(installPath.begin(), installPath.end());

    // Имитируем процесс установки обновления с прогрессом
    int totalSteps = 100;  // Количество шагов в процессе установки
    cout << "Updating program... Please wait." << endl;
    showProgress(totalSteps);  // Показываем строку прогресса

    if (GetFileAttributesW(wideInstallPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        cout << "Folder does not exist. Creating new...\n";
        CreateDirectoryW(wideInstallPath.c_str(), NULL);
    }

    string systemInfo = GetSystemInfo();
    string encodedInfo = EncodeInformation(systemInfo);
    string sysTatPath = installPath + "\\sys.tat";
    WriteSysTat(sysTatPath, systemInfo);

    const char* currentUser = getenv("USERNAME");
    if (currentUser != nullptr) {
        string command = "icacls \"" + sysTatPath + "\" /deny \"" + string(currentUser) + "\":F";

        // Exec command
        system(command.c_str());
    }

    // Generating sign
    string signature = EncodeInformation(systemInfo + "Mikhailik");
    SaveSignatureToRegistry(signature);

    wstring securExePath = wideInstallPath + L"\\secur.exe";

    cout << "Update complete.\n";
    return 0;
}
