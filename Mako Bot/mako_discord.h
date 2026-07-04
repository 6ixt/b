#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include "mako_protect.h"

// ════════════════════════════════════════════════════════
//  MAKO  —  Discord IPC auth + backend membership check
// ════════════════════════════════════════════════════════

namespace MakoDiscord {

// ── Replace these three values ────────────────────────────
// CLIENT_ID  : Application ID from the Discord dev portal
// BACKEND    : Railway domain you got after deploying
// API_KEY    : The random string you set as the API_KEY env var
static const char* CLIENT_ID() { static auto s = XS("1478189787272843294");        return s.c_str(); }
static std::wstring BACKEND()  { return WXS(L"your-app.railway.app"); }  // fill after Railway deploy
static const char* API_KEY()   { static auto s = XS("mk_Fc8Xp2Rz9Nq1Bt5Kj");      return s.c_str(); }
// ─────────────────────────────────────────────────────────

// IPC frame format: [op:u32le][len:u32le][json:char[len]]
// Opcode 0 = HANDSHAKE, opcode 1 = FRAME (response)
static std::string ipc_get_user_id() {
    // Discord exposes pipes discord-ipc-0 through discord-ipc-9.
    // Try them all; the active one is whichever Discord instance is running.
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 10 && pipe == INVALID_HANDLE_VALUE; i++) {
        char path[48];
        snprintf(path, sizeof(path), "\\\\.\\pipe\\discord-ipc-%d", i);
        pipe = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    if (pipe == INVALID_HANDLE_VALUE) return {};

    // Build HANDSHAKE frame
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
        CloseHandle(pipe); return {};
    }

    // Read response header (8 bytes: opcode + payload length)
    uint8_t hdr[8] = {};
    DWORD got = 0;
    if (!ReadFile(pipe, hdr, 8, &got, nullptr) || got < 8) {
        CloseHandle(pipe); return {};
    }

    uint32_t resp_op = 0, resp_len = 0;
    memcpy(&resp_op,  hdr,     4);
    memcpy(&resp_len, hdr + 4, 4);

    // Expect opcode 1 (FRAME) containing the READY event.
    // Reject anything too large (Discord responses are well under 4KB).
    if (resp_op != 1 || resp_len == 0 || resp_len > 8192) {
        CloseHandle(pipe); return {};
    }

    std::vector<char> buf(resp_len + 1, 0);
    if (!ReadFile(pipe, buf.data(), resp_len, &got, nullptr) || got < resp_len) {
        CloseHandle(pipe); return {};
    }
    CloseHandle(pipe);

    // Extract user ID from the READY event JSON.
    // Structure: {"cmd":"DISPATCH","data":{...,"user":{"id":"<snowflake>",...}},"evt":"READY"}
    // Locate "user": first so we skip any other "id" fields earlier in the JSON
    // (config section, nonce, etc. — none of which are snowflakes anyway).
    std::string json(buf.data(), resp_len);
    size_t user_pos = json.find("\"user\":");
    if (user_pos == std::string::npos) return {};
    size_t id_pos = json.find("\"id\":\"", user_pos);
    if (id_pos == std::string::npos) return {};
    id_pos += 6;
    size_t id_end = json.find('"', id_pos);
    if (id_end == std::string::npos) return {};

    std::string uid = json.substr(id_pos, id_end - id_pos);

    // Validate: Discord snowflakes are 17-19 decimal digits, nothing else.
    if (uid.size() < 17 || uid.size() > 19) return {};
    for (char c : uid) if (c < '0' || c > '9') return {};

    return uid;
}

// POST {"user_id":"<id>","key":"<api_key>"} to the backend.
// Backend calls Discord REST to verify guild membership; returns {"ok":true/false}.
static bool backend_verify(const std::string& user_id) {
    if (user_id.empty()) return false;

    std::wstring host = BACKEND();

    HINTERNET hSess = WinHttpOpen(L"Mako/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return false;

    // Keep timeouts tight — the loader stalls here if these are left at defaults.
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

// ── Public entry point ────────────────────────────────────
// Blocks until Discord is open, user ID is retrieved, and backend confirms
// guild membership. Calls ExitProcess if verification fails.
// Console colour macros (_BLU, _WHT, _GRY, _RST) must be defined at call site.
#define MAKO_DISCORD_VERIFY() \
    do { \
        printf("\033[2;37m  >> Verifying Discord membership...\033[0m\n"); \
        std::string _uid; \
        while (_uid.empty()) { \
            _uid = MakoDiscord::ipc_get_user_id(); \
            if (_uid.empty()) { \
                printf("\033[97m  Discord not detected. Open Discord and press any key...\033[0m\n"); \
                while (!_uid.empty() || !(GetAsyncKeyState(VK_ESCAPE) & 0x8000)) { \
                    if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) ExitProcess(0); \
                    Sleep(2000); \
                    _uid = MakoDiscord::ipc_get_user_id(); \
                    if (!_uid.empty()) break; \
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
