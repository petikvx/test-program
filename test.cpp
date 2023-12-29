#include <stdio.h>
#include <windows.h>

int main() {
    HKEY hKey;
	
    TCHAR windowsPath[MAX_PATH];
    TCHAR systemPath[MAX_PATH];

    DWORD windowsPathSize = GetWindowsDirectory(windowsPath, MAX_PATH);
    DWORD systemPathSize = GetSystemDirectory(systemPath, MAX_PATH);

    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey);

    if (result == ERROR_SUCCESS) {
        char machineGuid[256];
        DWORD dataSize = sizeof(machineGuid);
        DWORD dataType;
		

        result = RegQueryValueEx(hKey, "MachineGuid", NULL, &dataType, (LPBYTE)machineGuid, &dataSize);

        if (result == ERROR_SUCCESS) {
            machineGuid[dataSize] = '\0'; // Null-terminate the string.

            char message[512];
            snprintf(message, sizeof(message), "MachineGuid: %s", machineGuid);

            MessageBox(NULL, message, "MachineGuid", MB_ICONINFORMATION);
        } else {
            MessageBox(NULL, "Erreur lors de la lecture de la clé de registre", "Erreur", MB_ICONERROR);
        }

        RegCloseKey(hKey);
    } else {
        MessageBox(NULL, "Erreur lors de l'ouverture de la clé de registre", "Erreur", MB_ICONERROR);
    }
	


    if (windowsPathSize > 0 && systemPathSize > 0) {
        TCHAR message[1024];
        _stprintf(message, _T("Dossier Windows : %s\nDossier System : %s"), windowsPath, systemPath);

        MessageBox(NULL, message, _T("Informations sur les dossiers"), MB_ICONINFORMATION);
    } else {
        MessageBox(NULL, _T("Erreur lors de l'obtention des chemins des dossiers"), _T("Erreur"), MB_ICONERROR);
    }

    return 0;
}
