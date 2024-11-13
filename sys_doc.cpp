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
std::string GetSystemInfo() {
    std::stringstream sysInfo;
    HKEY hKey;

    // Получение имени пользователя и имени компьютера
    char userName[256];
    DWORD userNameSize = sizeof(userName);
    if (GetUserNameA(userName, &userNameSize)) {
        sysInfo << "User Name: " << userName << std::endl;
    }

    char computerName[256];
    DWORD computerNameSize = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameSize)) {
        sysInfo << "Computer Name: " << computerName << std::endl;
    }

    // Функция для чтения строкового значения из реестра
    auto ReadRegistryString = [](HKEY root, LPCWSTR subKey, LPCWSTR valueName) -> std::string {
        HKEY hKey;
        if (RegOpenKeyExW(root, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return "Error";
        }

        DWORD size = 0;
        DWORD type = 0;

        // Получаем размер буфера для значения
        if (RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &size) != ERROR_SUCCESS || type != REG_SZ) {
            RegCloseKey(hKey);
            return "Error";
        }

        std::wstring wresult(size / sizeof(wchar_t), L'\0');
        if (RegQueryValueExW(hKey, valueName, NULL, NULL, reinterpret_cast<LPBYTE>(&wresult[0]), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            // Преобразуем wstring в string
            std::string result(wresult.begin(), wresult.end());
            return result;
        }

        RegCloseKey(hKey);
        return "Error";
    };

    // ================== Информация о процессоре ==================
    sysInfo << "Processor Name: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString") << std::endl;
    sysInfo << "Processor Vendor: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"VendorIdentifier") << std::endl;

    // ================== Версия BIOS ==================
    sysInfo << "BIOS Vendor: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor") << std::endl;
    sysInfo << "BIOS Version: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion") << std::endl;

    // ================== Окружение системы ==================
    sysInfo << "Number of Processors: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"NUMBER_OF_PROCESSORS") << std::endl;
    sysInfo << "Operating System: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"OS") << std::endl;
    sysInfo << "Processor Architecture: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"PROCESSOR_ARCHITECTURE") << std::endl;
    sysInfo << "Processor Identifier: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"PROCESSOR_IDENTIFIER") << std::endl;

    // ================== Версия Windows ==================
    sysInfo << "Windows Product Name: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName") << std::endl;
    sysInfo << "Windows Release ID: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId") << std::endl;
    sysInfo << "Windows Build Number: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber") << std::endl;
    sysInfo << "Windows Registered Owner: " << ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"RegisteredOwner") << std::endl;

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
