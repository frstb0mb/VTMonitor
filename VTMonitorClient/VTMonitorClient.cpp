#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winioctl.h>
#include <DbgHelp.h>
#include <vector>
#include "common.h"
#include "PE.h"

// https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html
typedef struct _PS_ATTRIBUTE
{
    ULONG Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#pragma comment(lib, "DbgHelp.lib")


extern "C" uint64_t syscall_stub(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9, uint64_t rax, uint64_t rsp);

// We just access address to call #PF handler
// MSVC compiler is clever...
#pragma optimize("", off)
void ForceRead(uint64_t *addr)
{
    uint64_t dummy = *addr;
}

void ForceWrite(uint64_t *addr)
{
    uint64_t data = *addr;
    *addr = data;
}
#pragma optimize("", on)

constexpr uint64_t MAX_SYSCALL = 0x200;
class syscallinfo
{
private:
    std::string name_;
    bool (*cb_)(PCONTEXT);
    void PrintFuncname()
    {
        wprintf(L"%S\n", name_.c_str());
    }
public:
    syscallinfo() : cb_(nullptr) {};
    syscallinfo(const std::string& name, bool (*cb)(PCONTEXT)) : name_(name), cb_(cb) {};

    void assign(const std::string& name, bool (*cb)(PCONTEXT) = nullptr)
    {
        name_ = name;
        cb_ = cb;
    }

    bool call(PCONTEXT context)
    {
        PrintFuncname();
        if (cb_)
            return cb_(context);
        else
            return true;
    }
};

BYTE rip_backup;
BYTE dispatcher_backup;
FARPROC dispatcher = nullptr;

bool SetBP(PBYTE rip)
{
    // Proceed until iret
    if (!dispatcher) {
        auto ntdll = GetModuleHandleW(L"ntdll");
        if (!ntdll) {
            return false;
        }

        dispatcher = GetProcAddress(ntdll, "KiUserExceptionDispatcher");
        if (!dispatcher) {
            return false;
        }
    }

    DWORD protect_rip = 0;
    DWORD protect_disp = 0;
    if (!VirtualProtect(rip, 1, PAGE_EXECUTE_READWRITE, &protect_rip)) {
        return false;
    }
    if (!VirtualProtect(dispatcher, 1, PAGE_EXECUTE_READWRITE, &protect_disp)) {
        return false;
    }

    rip_backup = *rip;
    dispatcher_backup = *reinterpret_cast<BYTE*>(dispatcher);
    //*rip = 0xCC;
    *reinterpret_cast<BYTE*>(dispatcher) = 0xCC;

    if (!VirtualProtect(rip, 1, protect_rip, &protect_rip)) {
        return false;
    }
    if (!VirtualProtect(dispatcher, 1, protect_disp, &protect_disp)) {
        return false;
    }

    return true;
}

bool RmoveBP(PBYTE rip)
{
    DWORD protect_rip = 0;
    DWORD protect_disp = 0;
    if (!VirtualProtect(rip, 1, PAGE_EXECUTE_READWRITE, &protect_rip)) {
        return false;
    }
    if (!VirtualProtect(dispatcher, 1, PAGE_EXECUTE_READWRITE, &protect_disp)) {
        return false;
    }
    //*rip = rip_backup;
    *reinterpret_cast<BYTE*>(dispatcher) = dispatcher_backup;
    if (!VirtualProtect(rip, 1, protect_rip, &protect_rip)) {
        return false;
    }
    if (!VirtualProtect(dispatcher, 1, protect_disp, &protect_disp)) {
        return false;
    }

    return true;
}

bool ExitHandler(vtmif *vmdata, std::vector<syscallinfo> &table)
{
    if (!vmdata)
        return false;

    switch (vmdata->exitcode) {
        case 0:
        {
            switch(vmdata->vec) {
                // syscall assumed
                case EXCEPTION_BP:
                {
                    RmoveBP(reinterpret_cast<PBYTE>(vmdata->context.Rip));
                    vmdata->valid_inject = FALSE;
                    break;
                }
                case EXCEPTION_UD:
                {
                    if (vmdata->context.Rax < table.size()) {
                        if (!table[vmdata->context.Rax].call(&vmdata->context))
                            return false;
                    }

                    vmdata->context.Rax = syscall_stub(vmdata->context.R10, vmdata->context.Rdx, vmdata->context.R8, vmdata->context.R9, vmdata->context.Rax, vmdata->context.Rsp);
                    break;
                }

                case EXCEPTION_PF:
                {
                    BYTE errmask = (uint64_t)vmdata->error & 0x1;
                    if (errmask) {
                        auto except_addr = (PVOID)vmdata->except_addr;
                        MEMORY_BASIC_INFORMATION info={};
                        VirtualQuery(except_addr, &info, sizeof(info));

                        // CopyOnWrite
                        if ((info.Protect == PAGE_WRITECOPY || info.Protect == PAGE_READWRITE || info.Protect == PAGE_EXECUTE_WRITECOPY) && (DWORD64)vmdata->error == 7) {
                            ForceWrite(reinterpret_cast<uint64_t*>(except_addr));
                            vmdata->valid_inject = FALSE;
                        }
                        else {
                            // Access Violation
                            SetBP((PBYTE)vmdata->context.Rip);
                        }
                    }
                    else {
                        // page does not exist
                        ForceRead(reinterpret_cast<uint64_t*>((PVOID)vmdata->except_addr));
                        vmdata->valid_inject = FALSE;
                    }

                    break;
                }

                default:
                    SetBP((PBYTE)vmdata->context.Rip);
                    break;
            }
            break;
        }
        case 1:
        case 0xa:
            break;
        default:
            wprintf(L"[INFO] Reason:%x is not expected\n", vmdata->exitcode);
            return false;
    }

    return true;
}

bool Terminate(PCONTEXT context)
{
    wprintf(L"[INFO] Terminate\n");
    return false;
}

bool PrintProcfile(PCONTEXT context)
{
    auto attrlist = *reinterpret_cast<PPS_ATTRIBUTE_LIST*>(context->Rsp + 0x58);
    wprintf(L"    Target %s\n", (wchar_t*)attrlist->Attributes[0].ValuePtr);
    return true;
}

bool MakeSyscallTable(std::vector<syscallinfo> &table)
{
    auto handle = GetModuleHandleW(L"ntdll.dll");
    if (!handle)
        return false;

    ULONG size = 0;
    auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ImageDirectoryEntryToData(handle, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size));
    if (!export_dir)
        return false;

    auto ntdll = reinterpret_cast<uint8_t*>(handle);

    DWORD* funcs = reinterpret_cast<DWORD*>(ntdll + export_dir->AddressOfFunctions);
    DWORD* names = reinterpret_cast<DWORD*>(ntdll + export_dir->AddressOfNames);
    uint16_t* ords = reinterpret_cast<uint16_t*>(ntdll + export_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* funcname = reinterpret_cast<char*>(ntdll + names[i]);
        if (funcname[0] == 'N' && funcname[1] == 't') {
            auto funcaddr = reinterpret_cast<DWORD*>(ntdll + funcs[ords[i]]);
            auto syscallnum = funcaddr[1];
            if (syscallnum >= table.size() || funcname == nullptr)
                continue;

            bool (*cb)(PCONTEXT) = nullptr;
            if (!strcmp(funcname, "NtCreateUserProcess"))
                cb = PrintProcfile;
            else if (!strcmp(funcname, "NtTerminateProcess"))
                cb = Terminate;

            table[syscallnum].assign(funcname, cb);
        }
    }

    return true;
}

void Virt(DWORD64 entry)
{
    //BYTE stack[0x3000] = {};
    constexpr SIZE_T stacksize = 10*1000*1000;
    auto stack = VirtualAlloc(0, stacksize, MEM_COMMIT, PAGE_READWRITE);
    if (!stack) {
        wprintf(L"[ERROR] Cannnot allocate memory for stack\n");
        return;
    }

    CONTEXT context = {};
    RtlCaptureContext(&context);
    context.Rip = entry;
    context.Rsp = (DWORD64)(stack) + (5 * 1000 * 1000 + 8);
    wprintf(L"[INFO] Stack is %llx, MaxStack is %llx\n", context.Rsp, (DWORD64)stack);

    auto device = CreateFileW(L"\\\\.\\VTMonitor", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        VirtualFree(stack, 0, MEM_FREE);
        return;
    }
        

    vtmif vmdata = {};
    memcpy_s(&(vmdata.context), sizeof(CONTEXT), &context, sizeof(CONTEXT));

    std::vector<syscallinfo> table(MAX_SYSCALL);
    if (!MakeSyscallTable(table)) {
        VirtualFree(stack, 0, MEM_FREE);
        return;
    }

    DWORD read = 0;
    try
    {
        auto teb_head = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
        const auto StackBase_bk     = teb_head->StackBase;
        const auto StackLimit_bk    = teb_head->StackLimit;
        while (true) {
            teb_head->StackBase     = static_cast<PBYTE>(stack) + stacksize;
            teb_head->StackLimit    = stack;
            DeviceIoControl(device, IOCTL_VTMONITOR_START, &vmdata, sizeof(vmdata), &vmdata, sizeof(vmdata), &read, nullptr);
            teb_head->StackBase     = StackBase_bk;
            teb_head->StackLimit    = StackLimit_bk;
            if (!ExitHandler(&vmdata, table))
                break;
        }
    }
    catch (...)
    {
    }

    VirtualFree(stack, 0, MEM_FREE);
}

int wmain(int argc, wchar_t **argv)
{
    DWORD64 virtentry = 0;
    if (argc > 1) {
        DWORD entry = 0;
        PRUNTIME_FUNCTION functables = nullptr;
        auto load = LoadPE(argv[1], entry, functables);
        if (!load) {
            wprintf(L"[ERROR] Loading is failed\n");
            return 0;
        }
        wprintf(L"[INFO] ENTRY:%llx\n", (DWORD64)(load.get()) + entry);
        getchar();
        Virt((DWORD64)(load.get()) + entry);
        if (functables) {
            RtlDeleteFunctionTable(functables);
        }
    }
    else {
        wprintf(L"[ERROR] Invalid arguments\n");
    }

    wprintf(L"Done\n");
}