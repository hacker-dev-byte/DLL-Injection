/*
MIT License

Copyright (c) 2024 hacker-dev-byte

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

﻿#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

int main()
{
    LPCTSTR process_name = _T("notepad.exe");

    LPCTSTR dll_name = _T("Dll.dll");

    DWORD pid = -1;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x0);

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe)) 
    {
        do 
        {
            if (_tcscmp(pe.szExeFile, process_name) == 0x0) 
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    LPVOID process_va_mem = VirtualAllocEx(process, NULL, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    TCHAR dll_path[MAX_PATH];

    GetFullPathName(dll_name, MAX_PATH, dll_path, NULL);

    WriteProcessMemory(process, process_va_mem, dll_path, (_tcslen(dll_path) + 0x1) * sizeof(TCHAR), NULL);

    HANDLE thread = CreateRemoteThread(process, NULL, 0x0, (LPTHREAD_START_ROUTINE)LoadLibrary, process_va_mem, 0x0, NULL);

    WaitForSingleObject(thread, INFINITE);

    VirtualFreeEx(process, process_va_mem, 0x0, MEM_RELEASE);
    CloseHandle(thread);
    CloseHandle(process);
}
