#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winioctl.h>
#include <DbgHelp.h>
#include <vector>
#include "common.h"

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

class pemap
{
private:
    HANDLE file;
    HANDLE map;
    PIMAGE_DOS_HEADER dosheader;
    PIMAGE_NT_HEADERS ntheader;

    void clear()
    {
        ntheader = NULL;
        if (dosheader) {
            UnmapViewOfFile(dosheader);
            dosheader = NULL;
        }
        if (map) {
            CloseHandle(map);
            map = NULL;
        }
        if (file != INVALID_HANDLE_VALUE) {
            CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
        }
    }

public:
    pemap()
    {
        file = INVALID_HANDLE_VALUE;
        map = NULL;
        dosheader = NULL;
        ntheader = NULL;
    }
    ~pemap()
    {
        clear();
    }
    bool mapping(const wchar_t* filename)
    {
        if (filename == NULL)
            return false;

        file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
            return false;

        map = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!map) {
            clear();
            return false;
        }
        dosheader = reinterpret_cast<PIMAGE_DOS_HEADER>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
        if (!dosheader) {
            clear();
            return false;
        }

        try
        {
            if (dosheader->e_magic != 'ZM') {
                clear();
                return false;
            }
            ntheader = ImageNtHeader(dosheader);
            if (ntheader->Signature != 'EP' || ntheader->FileHeader.Machine != 0x8664 ||
                !(ntheader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
                clear();
                return false;
            }
            return true;
        }
        catch (...)
        {
        }

        return false;
    }
    const PIMAGE_DOS_HEADER getdos() const
    {
        return dosheader;
    }
    const PIMAGE_NT_HEADERS getnt() const
    {
        return ntheader;
    }
};

std::unique_ptr<BYTE[]> LoadPE(LPCWSTR path, DWORD &entry)
{
    // pemap for loading PE
    pemap loadinfo;
    if (!loadinfo.mapping(path)) {
        wprintf(L"[ERROR] pemap is faild\n");
        return nullptr;
    }

    // load
    auto loadsize = loadinfo.getnt()->OptionalHeader.SizeOfImage;
    auto loadedexe = std::make_unique<BYTE[]>(loadsize);
    DWORD oldprotect = 0;
    if (!VirtualProtect(loadedexe.get(), loadsize, PAGE_EXECUTE_READWRITE, &oldprotect)) {
        wprintf(L"[ERROR] VirtualProtect is failed %x\n", GetLastError());
        return nullptr;
    }

    // load DOS header and PE header
    memcpy_s(loadedexe.get(), loadsize, loadinfo.getdos(), loadinfo.getnt()->OptionalHeader.SizeOfHeaders);

    // load section data
    auto secheader = reinterpret_cast<PIMAGE_SECTION_HEADER>(loadinfo.getnt() + 1);
    ULONG_PTR lastaddr = reinterpret_cast<ULONG_PTR>(loadedexe.get()) + loadsize;
    auto dest = reinterpret_cast<ULONG_PTR>(loadedexe.get());
    auto src = reinterpret_cast<ULONG_PTR>(loadinfo.getdos());
    for (int i = 0; i < loadinfo.getnt()->FileHeader.NumberOfSections; i++) {
        auto destaddr = reinterpret_cast<LPVOID>(dest + secheader[i].VirtualAddress);
        auto srcaddr = reinterpret_cast<LPVOID>(src + secheader[i].PointerToRawData);
        memcpy_s(destaddr, lastaddr - reinterpret_cast<ULONG_PTR>(destaddr), srcaddr, secheader[i].SizeOfRawData);
    }


    // relocation
    ULONG relocsize;
    auto relocdesc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ImageDirectoryEntryToData(loadinfo.getdos(), FALSE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &relocsize));
    if (!relocdesc) {
        wprintf(L"[ERROR] ImageDirectoryEntryToData is failed %x\n", GetLastError());
        return nullptr;
    }

    ULONG_PTR delta = dest - loadinfo.getnt()->OptionalHeader.ImageBase; // offset of between real and ideal
    ULONG sumbytes = 0;
    while (relocdesc->VirtualAddress && relocdesc->SizeOfBlock) {
        DWORD count = (relocdesc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD list = reinterpret_cast<PWORD>(relocdesc + 1);
        for (DWORD i = 0; i < count; i++) {
            if (list[i]) {
                auto ptr = reinterpret_cast<PULONG_PTR>(dest + relocdesc->VirtualAddress + (list[i] & 0xFFF)); // remain is type info but meaningless
                *ptr += delta;
            }
        }
        sumbytes += relocdesc->SizeOfBlock;
        relocdesc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG_PTR>(relocdesc) + relocdesc->SizeOfBlock);
    }

    // make IAT
    ULONG importsize = 0;
    auto importdesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ImageDirectoryEntryToData(loadinfo.getdos(), FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &importsize));
    if (!importdesc) {
        wprintf(L"[ERROR] ImageDirectoryEntryToData is failed %x\n", GetLastError());
        return nullptr;
    }
    while (importdesc->Characteristics) {
        auto mod = LoadLibraryA(reinterpret_cast<LPCSTR>(dest) + importdesc->Name); // loading necessary module
        if (!mod) {
            wprintf(L"[ERROR] LoadLibraryA is failed %x\n", GetLastError());
            return nullptr;
        }

        auto origthunk = reinterpret_cast<PIMAGE_THUNK_DATA>(dest + importdesc->OriginalFirstThunk);
        auto firsthutnk = reinterpret_cast<PIMAGE_THUNK_DATA>(dest + importdesc->FirstThunk);

        while (origthunk->u1.AddressOfData) {
            LPCSTR procname = NULL;
            if (origthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Import by ordinal
                procname = reinterpret_cast<LPCSTR>(origthunk->u1.Ordinal & 0xFFFF);
            }
            else {
                // Import by name
                auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dest + origthunk->u1.AddressOfData);
                procname = reinterpret_cast<LPCSTR>(ibn->Name);
            }
            ULONG_PTR funcaddr = reinterpret_cast<ULONG_PTR>(GetProcAddress(mod, procname));
            if (!funcaddr) {
                wprintf(L"[ERROR] GetProcAddress is failed %x\n", GetLastError());
                return nullptr;
            }
            firsthutnk->u1.Function = funcaddr;

            firsthutnk++;
            origthunk++;
        }
        importdesc++;
    }

    wprintf(L"[INFO] Loadaddr %llx\n", dest + loadinfo.getnt()->OptionalHeader.AddressOfEntryPoint);
    entry = loadinfo.getnt()->OptionalHeader.AddressOfEntryPoint;
    return loadedexe;
}

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

bool ExitHandler(vtmif *vmdata, std::vector<syscallinfo> &table)
{
    if (!vmdata)
        return false;

    switch (vmdata->exitcode) {
        
        case 0:
        {
            switch(vmdata->vec) {
                // syscall assumed
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
                        if ((info.Protect == PAGE_WRITECOPY || info.Protect == PAGE_READWRITE || info.Protect == PAGE_EXECUTE_WRITECOPY) && (DWORD64)vmdata->error == 7)
                            ForceWrite(reinterpret_cast<uint64_t*>(except_addr));
                        else {
                            // currently not supported
                            wprintf(L"[INFO] PF Access Violation\n");
                            return false;
                        }
                    }
                    else
                        // page does not exist
                        ForceRead(reinterpret_cast<uint64_t*>((PVOID)vmdata->except_addr));

                    break;
                }
            }
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
    auto stack = VirtualAlloc(0, 10*1000*1000, MEM_COMMIT, PAGE_READWRITE);
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
        while (true) {
            DeviceIoControl(device, IOCTL_VTMONITOR_START, &vmdata, sizeof(vmdata), &vmdata, sizeof(vmdata), &read, nullptr);
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
        auto load = LoadPE(argv[1], entry);
        if (!load) {
            wprintf(L"[ERROR] Loading is failed\n");
            return 0;
        }
        wprintf(L"[INFO] ENTRY:%llx\n", (DWORD64)(load.get()) + entry);
        getchar();
        Virt((DWORD64)(load.get()) + entry);
    }
    else {
        wprintf(L"[ERROR] Invalid arguments\n");
    }

    wprintf(L"Done\n");
}