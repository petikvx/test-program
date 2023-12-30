#include <Windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    // Chemin vers le processus cible
    const char* targetProcessPath = "C:\\Windows\\System32\\notepad.exe";

    // Message à afficher dans la boîte de message
    const char* message = "Message injecté depuis un autre processus!";

    // Ouvrir le processus cible
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    if (CreateProcess(targetProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        // Allouer de la mémoire dans le processus cible pour le message
        LPVOID remoteMemory = VirtualAllocEx(pi.hProcess, NULL, strlen(message) + 1, MEM_COMMIT, PAGE_READWRITE);

        // Écrire le message dans la mémoire du processus cible
        WriteProcessMemory(pi.hProcess, remoteMemory, message, strlen(message) + 1, NULL);

        // Adresse de la fonction MessageBoxA dans le processus cible (user32.dll)
        FARPROC MessageBoxAddr = GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");

        // Créer un thread dans le processus cible pour exécuter MessageBoxA
        HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)MessageBoxAddr, remoteMemory, 0, NULL);

        // Attendre la fin du thread
        WaitForSingleObject(hThread, INFINITE);

        // Fermer les handles
        CloseHandle(hThread);
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("Erreur lors de la création du processus cible.\n");
    }

    return 0;
}
