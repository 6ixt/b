#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include "mako_protect.h"

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  MAKO  â€”  Discord IPC auth + backend membership check
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

namespace MakoDiscord {

static const char*   CLIENT_ID() { static auto s = XS("1517965290829254657");      return s.c_str(); }
static std::wstring  BACKEND()   { return WXS(L"b-production-f80c.up.railway.app"); }
static const char*   API_KEY()   { static auto s = XS("mk_Fc8Xp2Rz9Nq1Bt5Kj");    return s.c_str(); }

static std::string ipc_get_user_id() {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    int found_i = -1;
    for (int i = 0; i < 10 && pipe == INVALID_HANDLE_VALUE; i++) {
        char path[48];
        snprintf(path, sizeof(path), "\\\\.\\pipe\\discord-ipc-%d", i);
        pipe = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) found_i = i;
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        printf("  [ipc] pipe not found (err %lu)\n", GetLastError());
        return {};
    }
    printf("  [ipc] connected to discord-ipc-%d\n", found_i);

    char payload[256];
    int plen = snprintf(payload, sizeof(payload),
                        "{\"v\":1,\"client_id\":\"%s\"}", CLIENT_ID());
    if (plen <= 0 || plen >= (int)sizeof(payload)) { CloseHandle(pipe); return {}; }

    uint8_t frame[8 + 256];
    uint32_t op = 0, ulen = (uint32_t)plen;
    memcpy(frame,     &op,   4);
    memcpy(frame + 4, &ulen, 4);
    memcpy(frame + 8, payload, plen);

    DWORD written = 0;
    if (!WriteFile(pipe, frame, 8 + plen, &written, nullptr) || written != (DWORD)(8 + plen)) {
        printf("  [ipc] write failed (err %lu, wrote %lu/%d)\n", GetLastError(), written, 8 + plen);
        CloseHandle(pipe); return {};
    }
    printf("  [ipc] handshake sent (%d bytes)\n", 8 + plen);

    uint8_t hdr[8] = {};
    DWORD got = 0;
    if (!ReadFile(pipe, hdr, 8, &got, nullptr) || got < 8) {
        printf("  [ipc] header read failed (err %lu, got %lu)\n", GetLastError(), got);
        CloseHandle(pipe); return {};
    }

    uint32_t resp_op = 0, resp_len = 0;
    memcpy(&resp_op,  hdr,     4);
    memcpy(&resp_len, hdr + 4, 4);
    printf("  [ipc] response op=%u len=%u\n", resp_op, resp_len);

    if (resp_op != 1 || resp_len == 0 || resp_len > 8192) {
        // Read and print the payload anyway so we can see the error message
        if (resp_len > 0 && resp_len <= 8192) {
            std::vector<char> ebuf(resp_len + 1, 0);
            DWORD er = 0;
            ReadFile(pipe, ebuf.data(), resp_len, &er, nullptr);
            printf("  [ipc] discord says: %.*s\n", (int)er, ebuf.data());
        }
        CloseHandle(pipe); return {};
    }

    std::vector<char> buf(resp_len + 1, 0);
    if (!ReadFile(pipe, buf.data(), resp_len, &got, nullptr) || got < resp_len) {
        printf("  [ipc] payload read failed (err %lu, got %lu/%u)\n", GetLastError(), got, resp_len);
        CloseHandle(pipe); return {};
    }
    CloseHandle(pipe);
    printf("  [ipc] got payload: %.120s\n", buf.data());

    std::string json(buf.data(), resp_len);
    size_t user_pos = json.find("\"user\":");
    if (user_pos == std::string::npos) { printf("  [ipc] no 'user' in json\n"); return {}; }
    size_t id_pos = json.find("\"id\":\"", user_pos);
    if (id_pos == std::string::npos) { printf("  [ipc] no 'id' in user obj\n"); return {}; }
    id_pos += 6;
    size_t id_end = json.find('"', id_pos);
    if (id_end == std::string::npos) return {};

    std::string uid = json.substr(id_pos, id_end - id_pos);
    if (uid.size() < 17 || uid.size() > 19) { printf("  [ipc] bad snowflake: %s\n", uid.c_str()); return {}; }
    for (char c : uid) if (c < '0' || c > '9') { printf("  [ipc] non-digit in id\n"); return {}; }

    printf("  [ipc] user id: %s\n", uid.c_str());
    return uid;
}

static bool backend_verify(const std::string& user_id) {
    if (user_id.empty()) return false;

    std::wstring host = BACKEND();

    HINTERNET hSess = WinHttpOpen(L"Mako/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return false;

    DWORD ms = 6000;
    WinHttpSetOption(hSess, WINHTTP_OPTION_CONNECT_TIMEOUT, &ms, sizeof(ms));
    WinHttpSetOption(hSess, WINHTTP_OPTION_SEND_TIMEOUT,    &ms, sizeof(ms));
    WinHttpSetOption(hSess, WINHTTP_OPTION_RECEIVE_TIMEOUT, &ms, sizeof(ms));

    HINTERNET hConn = WinHttpConnect(hSess, host.c_str(),
                                      INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return false; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", L"/verify",
                                         nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
    if (!hReq) {
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        return false;
    }

    WinHttpAddRequestHeaders(hReq,
        L"Content-Type: application/json\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    char body[256];
    int  blen = snprintf(body, sizeof(body),
                         "{\"user_id\":\"%s\",\"key\":\"%s\"}",
                         user_id.c_str(), API_KEY());

    bool ok = false;
    if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            body, blen, blen, 0) &&
        WinHttpReceiveResponse(hReq, nullptr))
    {
        DWORD status = 0, ssz = sizeof(status);
        WinHttpQueryHeaders(hReq,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &status, &ssz, WINHTTP_NO_HEADER_INDEX);

        if (status == 200) {
            char rbuf[128] = {};
            DWORD avail = 0, rd = 0;
            WinHttpQueryDataAvailable(hReq, &avail);
            if (avail && avail < sizeof(rbuf))
                WinHttpReadData(hReq, rbuf, avail, &rd);
            ok = (strstr(rbuf, "\"ok\":true") != nullptr);
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return ok;
}

#define MAKO_DISCORD_VERIFY() \
    do { \
        printf("\033[2;37m  >> Verifying Discord membership...\033[0m\n"); \
        std::string _uid; \
        while (_uid.empty()) { \
            _uid = MakoDiscord::ipc_get_user_id(); \
            if (_uid.empty()) { \
                printf("\033[97m  Discord not detected. Open Discord and try again...\033[0m\n"); \
                for (int _i = 0; _i < 3; _i++) { \
                    if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) ExitProcess(0); \
                    Sleep(1000); \
                } \
            } \
        } \
        printf("\033[97m  Checking server membership...\033[0m\n"); \
        if (!MakoDiscord::backend_verify(_uid)) { \
            printf("\033[97m  Access denied. Join discord.gg/makohq to use Mako.\033[0m\n"); \
            Sleep(4000); \
            ExitProcess(0); \
        } \
        printf("\033[97m  Access granted.\033[0m\n"); \
        Sleep(350); \
    } while (0)

} // namespace MakoDiscord
