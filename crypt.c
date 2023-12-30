#include <stdio.h>
#include <windows.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <winbase.h>
#include <Shlwapi.h>
#include <wincrypt.h>
#include <base64.h>

// Function to read a file and return its content
bool readFile(const char *filename, char **content, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        return false;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *content = (char *)VirtualAlloc(NULL, *size, MEM_COMMIT, PAGE_READWRITE);
    if (*content == NULL) {
        fclose(file);
        return false;
    }

    fread(*content, 1, *size, file);
    fclose(file);

    return true;
}

// Function to write content to a file with .base64 extension
bool writeBase64File(const char *filename, const char *base64Content, size_t size) {
    char base64Filename[MAX_PATH];
    PathRenameExtensionA(base64Filename, ".base64");

    FILE *file = fopen(base64Filename, "wb");
    if (file == NULL) {
        return false;
    }

    fwrite(base64Content, 1, size, file);
    fclose(file);

    return true;
}

// Function to write a message to a log file
void writeLog(const char *message, const char *tempDirectory) {
    char logPath[MAX_PATH];
    snprintf(logPath, MAX_PATH, "%s\\logptk.log", tempDirectory);

    FILE *logFile = fopen(logPath, "a");
    if (logFile != NULL) {
        fprintf(logFile, "%s\n", message);
        fclose(logFile);
    }
}

// Recursive function to traverse folders and process files
void traverseDirectory(const char *directory, const char *tempDirectory) {
    WIN32_FIND_DATAA fileData;
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\*.{txt,pdf,html}", directory);
    HANDLE findHandle = FindFirstFileA(path, &fileData);

    if (findHandle != INVALID_HANDLE_VALUE) {
        do {
            char filePath[MAX_PATH];
            snprintf(filePath, MAX_PATH, "%s\\%s", directory, fileData.cFileName);

            if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // If it's a directory, recursively explore it
                if (strcmp(fileData.cFileName, ".") != 0 && strcmp(fileData.cFileName, "..") != 0) {
                    traverseDirectory(filePath, tempDirectory);
                }
            } else {
                // If it's a file, process it as before
                char *content = NULL;
                size_t size = 0;

                if (readFile(filePath, &content, &size)) {
                    char *base64Content = NULL;
                    size_t base64Size = 0;

                    if (Base64Encode(content, size, &base64Content, &base64Size)) {
                        if (writeBase64File(filePath, base64Content, base64Size)) {
                            printf("File %s has been converted to base64 and saved as %s.base64\n", filePath, filePath);
                            writeLog(filePath, tempDirectory); // Write the file name to the log
                        } else {
                            printf("Failed to write %s.base64\n", filePath);
                        }

                        VirtualFree(base64Content, 0, MEM_RELEASE);
                    } else {
                        printf("Failed to convert %s to base64\n", filePath);
                    }

                    VirtualFree(content, 0, MEM_RELEASE);
                } else {
                    printf("Failed to read %s\n", filePath);
                }
            }
        } while (FindNextFileA(findHandle, &fileData) != 0);

        FindClose(findHandle);
    }
}

int main() {
    char tempDirectory[MAX_PATH];
    DWORD result = GetTempPathA(MAX_PATH, tempDirectory);

    if (result == 0) {
        printf("Failed to retrieve the temporary directory.\n");
        return 1;
    }

    traverseDirectory(".", tempDirectory); // Start exploration from the current directory

    char windowsDirectory[MAX_PATH];
    DWORD windowsDirSize = GetWindowsDirectoryA(windowsDirectory, MAX_PATH);
    if (windowsDirSize != 0) {
        traverseDirectory(windowsDirectory, tempDirectory); // Explore the Windows directory
    } else {
        printf("Failed to get the Windows directory.\n");
    }

    char systemDirectory[MAX_PATH];
    DWORD systemDirSize = GetSystemDirectoryA(systemDirectory, MAX_PATH);
    if (systemDirSize != 0) {
        traverseDirectory(systemDirectory, tempDirectory); // Explore the System directory
    } else {
        printf("Failed to get the System directory.\n");
    }

    return 0;
}
