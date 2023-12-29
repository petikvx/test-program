#include <stdio.h>
#include <windows.h>

int main() {
    HKEY hKey;
	
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
	

    return 0;
}
