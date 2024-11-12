// g++ -I "C:\Program Files\OpenSSL-Win64\include" -L "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MDd" .\secur.cpp -o .\secur.exe "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MDd\libcrypto.lib" 
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

// Функция для получения подписи из реестра
string GetSignatureFromRegistry(const string& registryPath) {
    HKEY hKey;
    string signature = "";
    if (RegOpenKeyExA(HKEY_CURRENT_USER, registryPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {  // Используем RegOpenKeyExA
        DWORD size;
        RegQueryValueExA(hKey, "Signature", NULL, NULL, NULL, &size);  // Используем RegQueryValueExA
        char* value = new char[size];
        RegQueryValueExA(hKey, "Signature", NULL, NULL, (LPBYTE)value, &size);
        signature = string(value);
        delete[] value;
        RegCloseKey(hKey);
    }
    return signature;
}

// Функция для проверки подписи
bool VerifySignature(const string& userKey, const string& savedSignature, const string&fileContents) {
    string signature = EncodeInformation(fileContents + userKey);
    return signature == savedSignature;
}




int main() {
    // 1. Запрашиваем у пользователя раздел реестра с подписью
    cout << "Enter the key to get access: ";
    string userKey;
    getline(cin, userKey);

    // Чтение всего содержимого файла
    stringstream buffer;
    string icaclsCommand = "icacls sys.tat /reset";
    string attribCommand = "attrib -h -s -r sys.tat";

    system(icaclsCommand.c_str());
    system(attribCommand.c_str());

    string filePath = "sys.tat";
    ifstream file(filePath);

    if (!file) {
        cerr << "Error while opening the file!" << endl;
        return 1;
    }

    buffer << file.rdbuf();  // Читаем файл в stringstream

    const char* currentUser = getenv("USERNAME");
    string attribCommand_after = "attrib +h +s +r sys.tat";
    string icaclsCommand_after = "icacls sys.tat /deny \"" + string(currentUser) + "\":F";
    system(attribCommand_after.c_str());
    system(icaclsCommand_after.c_str());

    // Преобразование содержимого в строку
    string fileContents = buffer.str();

    // 2. Считываем подпись из реестра
    string savedSignature = GetSignatureFromRegistry("SOFTWARE\\Mikhailik");

    if (savedSignature.empty()) {
        cout << "Signature not found in registry!" << endl;
        return 1;
    }

    // 4. Проверяем подпись
    if (VerifySignature(userKey, savedSignature, fileContents)) {
        cout << "Signature is correct, access to sys.tat allowed." << endl;
        string icaclsCommand = "icacls sys.tat /reset";
        string attribCommand = "attrib -h -s -r sys.tat";
        system(icaclsCommand.c_str());
        system(attribCommand.c_str());

    } else {
        cout << "Wrong key! Access denied." << endl;
    }

    return 0;
}
