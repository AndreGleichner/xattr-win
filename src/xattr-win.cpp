#include "pch.h"

#include "argh.h"

#pragma comment(lib, "ntdll")

// clang-format off
/*

Status code                                     Meaning
-- WARNING --
STATUS_BUFFER_OVERFLOW          0x80000005      The output buffer was filled before all of the EA data could be returned. Only complete FILE_FULL_EA_INFORMATION structures are returned.
STATUS_NO_MORE_EAS              0x80000012      No more extended attributes (EAs) were found for the file.
STATUS_INVALID_EA_NAME          0x80000013      The specified extended attribute (EA) name contains at least one illegal character.
                                                An array of 8-bit ASCII characters that contains the extended attribute name followed by a single terminating null character byte.
                                                The EaName MUST be less than 255 characters and MUST NOT contain any of the following characters:
                                                ASCII values 0x00 - 0x1F, \ / : * ? " < > | , + = [ ] ;
STATUS_EA_LIST_INCONSISTENT     0x80000014      The extended attribute (EA) list is inconsistent.
STATUS_INVALID_EA_FLAG          0x80000015      An invalid extended attribute (EA) flag was set.

-- ERROR --
STATUS_INVALID_DEVICE_REQUEST   0xC0000010      The specified request is not a valid operation for the target device.
STATUS_ACCESS_DENIED            0xC0000022      A process has requested access to an object, but has not been granted those access rights.
STATUS_BUFFER_TOO_SMALL         0xC0000023      The buffer is too small to contain the entry. No information has been written to the buffer.
STATUS_EAS_NOT_SUPPORTED        0xC000004F      An operation involving EAs failed because the file system does not support EAs.
STATUS_EA_TOO_LARGE             0xC0000050      An EA operation failed because EA set is too large.
STATUS_NONEXISTENT_EA_ENTRY     0xC0000051      An EA operation failed because the name or EA index is invalid.
STATUS_NO_EAS_ON_FILE           0xC0000052      The file for which EAs were requested has no EAs.
STATUS_EA_CORRUPT_ERROR         0xC0000053      The EA is corrupt and non-readable.
STATUS_INSUFFICIENT_RESOURCES   0xC000009A      Insufficient system resources exist to complete the API.

*/
// clang-format on


class Codepage
{
public:
    Codepage()
    {
        cp_  = GetConsoleCP();
        ocp_ = GetConsoleOutputCP();

        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
    }
    ~Codepage()
    {
        SetConsoleCP(cp_);
        SetConsoleOutputCP(ocp_);
    }

private:
    UINT cp_, ocp_;
};

class ExitProgram : public std::exception
{
public:
    int code;
    ExitProgram(int code) : code(code)
    {
    }
};

class Program
{
public:
    Program(const std::string_view name) : name_(name)
    {
        codepage_ = std::make_unique<Codepage>();
    }
    ~Program()
    {
        inCtor_ = true;
        Exit(0);
    }

    void Exit(const int exit_code = 0, const std::wstring_view msg = L"")
    {
        if (exited_)
            return;

        exited_ = true;

        if (exit_code)
            std::wcerr << UTF8ToWide(name_) << L" exited with code " << exit_code << ": " << msg << std::endl;

        fflush(nullptr);
        codepage_.reset();

        if (!inCtor_)
            throw ExitProgram(exit_code);
    }

    void Usage()
    {
    }

private:
    std::string               name_;
    std::unique_ptr<Codepage> codepage_;
    bool                      exited_ {false};
    bool                      inCtor_ {false};
};

std::unique_ptr<Program> g_pgm;

class WideArgv
{
public:
    WideArgv(const int argc, const wchar_t* const* const argv, bool skipFirst = true)
    {
        u8_args_.reserve(argc);
        std::transform(argv, argv + argc, std::back_inserter(u8_args_), WideToUTF8);

        bool first = true;
        for (const auto& s : u8_args_)
        {
            if (!skipFirst || !first)
                argv_.push_back(s.c_str());

            first = false;
        }
        argv_.push_back(nullptr);
    }
    const char** operator()()
    {
        return &argv_[0];
    }

private:
    std::vector<std::string> u8_args_;
    std::vector<const char*> argv_;
};

const size_t MAX_EA_VALUE_BYTES = MAXUSHORT;
const size_t MAX_EA_NAME_LENGTH = 254;

struct EaConf
{
    enum class Cmd
    {
        Invalid,
        List,
        Print,
        Write,
        Delete,
        Clear
    };

    EaConf() = default;

    bool Parse(const argh::parser& cmdl)
    {
        int firstFileIndex = 0;
        // Print value of EA ea_name on the given file(s):
        // xattr -p[-lrvx] ea_name file [ file ... ]
        if (cmdl[{"-p"}] && cmdl.pos_args().size() >= 2)
        {
            Command        = Cmd::Print;
            EaName         = cmdl[0];
            firstFileIndex = 1;
        }
        // Write the value of the EA ea_name to ea_value:
        // xattr -w[-rux] ea_name ea_value file [ file ... ]
        else if (cmdl[{"-w"}] && cmdl.pos_args().size() >= 3)
        {
            Command        = Cmd::Write;
            EaName         = cmdl[0];
            EaValue        = cmdl[1];
            firstFileIndex = 2;
        }
        // Delete the EA ea_name from file(s):
        // xattr -d[-rv] ea_name file [ file ... ]
        else if (cmdl[{"-d"}] && cmdl.pos_args().size() >= 2)
        {
            Command        = Cmd::Delete;
            EaName         = cmdl[0];
            firstFileIndex = 1;
        }
        // Clear all EA from the given file(s):
        // xattr -c[-rv] file [ file ... ]
        else if (cmdl[{"-c"}] && cmdl.pos_args().size() >= 1)
        {
            Command = Cmd::Clear;
        }
        // List only the names of all EAs on the given file(s):
        // xattr [-lrvx] file [ file ... ]
        else if (cmdl.pos_args().size() >= 1)
        {
            Command = Cmd::List;
        }

        // Validate name/value format
        // Invalid EA name chars: ASCII 0x00 - 0x1F, \ / : * ? " < > | , + = [ ] ;
        if (!EaName.empty())
        {
            std::wstring       name         = UTF8ToWide(EaName);
            const std::wstring invalidChars = L"\\/:*?\"<>|,+=[];";

            bool hasInvalidChars = std::any_of(name.begin(), name.end(), [&invalidChars](wchar_t ch) {
                return ch <= 0x1F || ch > 0xFF || invalidChars.find(ch) != std::wstring::npos;
            });

            if (hasInvalidChars)
            {
                g_pgm->Exit(1, L"EA name hat invalid characters.");
                // unreachable
                return false;
            }
            if (EaName.length() > MAX_EA_NAME_LENGTH)
            {
                g_pgm->Exit(1, L"EA name is too long.");
                // unreachable
                return false;
            }

            // Overwrite as ASCII, not UTF-8! Codepoints > 0x80 are converted into 2-byte UTF-8 sequences.
            EaName = WideToAscii(name);
        }

        if (Command != Cmd::Invalid)
        {
            int index = 0;
            for (const auto& file : cmdl.pos_args())
            {
                if (index++ >= firstFileIndex)
                    Files.push_back(UTF8ToWide(file));
            }

            Long      = cmdl[{"-p"}];
            Recursive = cmdl[{"-r"}];
            ViewFile  = cmdl[{"-v"}];
            Hex       = cmdl[{"-x"}];
            Unicode   = cmdl[{"-u"}];
            KeepGoing = cmdl[{"-k"}];
        }

        return Command != Cmd::Invalid;
    }

    Cmd Command {Cmd::Invalid};
    // 8-bit ASCII, excluding invalid EA chars 0x00 - 0x1F, \ / : * ? " < > | , + = [ ] ;
    std::string               EaName;
    std::string               EaValue;
    bool                      Long {false};
    bool                      Recursive {false};
    bool                      ViewFile {false};
    bool                      Hex {false};
    bool                      Unicode {false};
    bool                      KeepGoing {false};
    std::vector<std::wstring> Files;
};

class NativeFile
{
public:
    NativeFile() = default;

    ~NativeFile()
    {
        if (hFile_ != INVALID_HANDLE_VALUE)
            NtClose(hFile_);
    }


    bool WriteEa(const std::wstring& file, const EaConf& eaConf)
    {
        if (eaConf.EaName.length() == 0 || eaConf.EaName.length() > MAX_EA_NAME_LENGTH)
            return false;

        if (!eaConf.Hex && eaConf.EaValue.length() + 1 > MAX_EA_VALUE_BYTES)
            return false;

        std::vector<BYTE> bytes;
        if (eaConf.Hex)
        {
            bytes = ParseHexValue(eaConf.EaValue);
            if (bytes.empty() || bytes.size() > MAX_EA_VALUE_BYTES)
                return false;
        }
        else if (eaConf.Unicode)
        {
            bytes.resize((eaConf.EaValue.length() + 1) * sizeof(WCHAR));
            std::copy(eaConf.EaValue.begin(), eaConf.EaValue.end(), (WCHAR*)bytes.data());
        }
        else // as UTF-8
        {
            bytes.resize(eaConf.EaValue.length() + 1);
            std::copy(eaConf.EaValue.begin(), eaConf.EaValue.end(), bytes.begin());
        }

        if (!Open(file, true))
            return false;


        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information

        /*
typedef struct _FILE_FULL_EA_INFORMATION
{
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    _Field_size_bytes_(EaNameLength) CHAR EaName[1];
    // ...
    // UCHAR EaValue[1]
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
        */

        std::vector<BYTE> buffer(sizeof(FILE_FULL_EA_INFORMATION) + eaConf.EaName.length() + bytes.size());
        auto              info = (PFILE_FULL_EA_INFORMATION)buffer.data();

        info->EaNameLength  = (UCHAR)eaConf.EaName.length();
        info->EaValueLength = (USHORT)bytes.size();
        strcpy_s(info->EaName, eaConf.EaName.length() + 1, eaConf.EaName.c_str());
        memcpy_s((PVOID)(info->EaName + info->EaNameLength + 1), info->EaValueLength, bytes.data(), bytes.size());

        IO_STATUS_BLOCK ioStatus {};
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwseteafile
        NTSTATUS status = ZwSetEaFile(hFile_, &ioStatus, info, sizeof(buffer));

        return !!NT_SUCCESS(status);
    }

    const std::vector<std::pair<std::string, std::vector<BYTE>>> ReadEa(
        const std::wstring& file, const std::string& eaName = "")
    {
        std::vector<std::pair<std::string, std::vector<BYTE>>> eas;
        if (!Open(file, false))
            return eas;

        IO_STATUS_BLOCK   ioStatus {};
        std::vector<BYTE> buffer(sizeof(FILE_FULL_EA_INFORMATION) + MAX_EA_NAME_LENGTH + MAX_EA_VALUE_BYTES);
        NTSTATUS          status;
        BOOLEAN           restart = TRUE;

        for (;;)
        {
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryeafile
            status = ZwQueryEaFile(
                hFile_, &ioStatus, buffer.data(), (ULONG)buffer.size(), FALSE, nullptr, 0, nullptr, restart);
            if (!NT_SUCCESS(status))
                break;

            restart = FALSE;

            auto info = (FILE_FULL_EA_INFORMATION*)buffer.data();
            for (;;)
            {
                std::pair<std::string, std::vector<BYTE>> ea;

                ea.first = std::string(info->EaName, info->EaNameLength);
                if (eaName.empty() || 0 == _stricmp(eaName.c_str(), ea.first.c_str()))
                {
                    ea.second.resize(info->EaValueLength);

                    memcpy_s(ea.second.data(), info->EaValueLength, (PBYTE)(info->EaName + info->EaNameLength + 1),
                        info->EaValueLength);

                    eas.push_back(ea);
                }

                if (info->NextEntryOffset == 0)
                    break;

                info = (PFILE_FULL_EA_INFORMATION)((PBYTE)info + info->NextEntryOffset);
            }
        }

        return eas;
    }

    bool DeleteEa(const std::wstring& file, const std::string& eaName)
    {
        if (eaName.empty())
            g_pgm->Exit(1, L"EA name is empty");

        if (!Open(file, true))
            return false;

        union
        {
            FILE_FULL_EA_INFORMATION info {};
            BYTE                     buffer[MAX_EA_NAME_LENGTH];
        };
        strcpy_s(info.EaName, eaName.length() + 1, eaName.c_str());
        info.EaNameLength    = (UCHAR)eaName.length();
        info.NextEntryOffset = 0;
        info.EaValueLength   = 0;
        IO_STATUS_BLOCK ioStatus {};

        NTSTATUS status = ZwSetEaFile(hFile_, &ioStatus, &info, sizeof(info) + info.EaNameLength + 1);
        return !!NT_SUCCESS(status);
    }
    bool ClearEa(const std::wstring& file)
    {
        if (!Open(file, true))
            return false;

        auto currentEas = ReadEa(file);
        if (currentEas.empty())
            return true;

        for (const auto& ea : currentEas)
        {
            if (!DeleteEa(file, ea.first))
                return false;
        }
        return true;
    }
    static std::wstring CanonicalPath(const std::wstring& relativePath, bool nativePrefix = true)
    {
        DWORD size = GetFullPathNameW(relativePath.c_str(), 0, nullptr, nullptr);

        if (size == 0)
            return std::wstring {};

        std::vector<wchar_t> buffer(size);
        DWORD                result = GetFullPathNameW(relativePath.c_str(), size, buffer.data(), nullptr);

        if (result == 0 || result >= size)
            return std::wstring {};

        if (nativePrefix)
            return L"\\??\\" + std::wstring(buffer.data());

        return std::wstring(buffer.data());
    }

private:
    bool Open(const std::wstring& file, bool write)
    {
        if (hFile_ != INVALID_HANDLE_VALUE)
            return true;

        auto f = CanonicalPath(file);

        UNICODE_STRING name {};
        RtlInitUnicodeString(&name, f.c_str());

        OBJECT_ATTRIBUTES attr = RTL_CONSTANT_OBJECT_ATTRIBUTES(&name, 0);
        IO_STATUS_BLOCK   ioStatus {};

        NTSTATUS status = NtOpenFile(&hFile_, (write ? (FILE_WRITE_EA | FILE_READ_EA) : FILE_READ_EA) | SYNCHRONIZE,
            &attr, &ioStatus,
            FILE_SHARE_WRITE | FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

        return !!NT_SUCCESS(status);
    }

    std::string removeWhitespaces(const std::string& input)
    {
        std::string result = input;
        result.erase(std::remove_if(result.begin(), result.end(), ::isspace), result.end());
        return result;
    }

    std::vector<BYTE> ParseHexValue(const std::string& value)
    {
        std::string v = removeWhitespaces(value);

        if (v.length() % 2 != 0)
            return {};

        if (v.length() / 2 > MAX_EA_VALUE_BYTES)
            return {};

        std::vector<BYTE> bytes;
        bytes.reserve(v.length() / 2);
        for (size_t i = 0; i < v.length(); i += 2)
        {
            BYTE byte = (BYTE)strtol(v.substr(i, 2).c_str(), nullptr, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    HANDLE hFile_ {INVALID_HANDLE_VALUE};
};

class EaPrinter
{
public:
    EaPrinter(const EaConf& eaConf) : eaConf_(eaConf)
    {
    }

    void PrintEas(std::filesystem::path path, const std::vector<std::pair<std::string, std::vector<BYTE>>>& eas)
    {
        bool viewFile = eaConf_.ViewFile || eas.size() > 1;
        auto filename = path.filename().wstring();

        for (const auto& ea : eas)
        {
            if (viewFile)
                std::wcout << filename << L": ";

            std::cout << ea.first << ": ";
            if (eaConf_.Hex || AnyNonPrintable(ea.second))
            {
                PrintHex(ea.second);
            }
            else if (eaConf_.Unicode)
            {
                std::wcout << std::wstring((wchar_t*)ea.second.data(), ea.second.size() / 2);
            }
            else
            {
                std::cout << std::string((char*)ea.second.data(), ea.second.size());
            }
            std::cout << std::endl;
        }
    }

private:
    void PrintHex(const std::vector<BYTE>& bytes)
    {
        for (const auto& b : bytes)
        {
            std::cout << std::hex << b;
        }
    }

    bool AnyNonPrintable(const std::vector<BYTE>& bytes)
    {
        if (eaConf_.Unicode)
        {
            for (size_t i = 0; i < bytes.size(); i += 2)
            {
                wchar_t c = *(wchar_t*)&bytes[i];
                if (!iswprint(c))
                    return true;
            }
        }
        else
        {
            for (const auto& b : bytes)
            {
                if (!isprint(b))
                    return true;
            }
        }

        return false;
    }
    EaConf eaConf_;
};

class EaWorker
{
public:
    EaWorker(const EaConf& eaConf) : eaConf_(eaConf)
    {
    }

    void Exceute()
    {
        switch (eaConf_.Command)
        {
            case EaConf::Cmd::List:
                ExcecuteListOrPrint();
                break;
            case EaConf::Cmd::Print:
                ExcecuteListOrPrint();
                break;
            case EaConf::Cmd::Write:
                ExcecuteWrite();
                break;
            case EaConf::Cmd::Delete:
                ExcecuteDelete();
                break;
            case EaConf::Cmd::Clear:
                ExcecuteClear();
                break;
            default:
                break;
        }
    }

private:
    void ExcecuteListOrPrint()
    {
        NativeFile file;
        for (const auto& f : eaConf_.Files)
        {
            auto path = std::filesystem::path(f);

            if (std::filesystem::is_directory(path))
            {
                if (eaConf_.Recursive)
                {
                    const std::filesystem::directory_options dir_opt =
                        std::filesystem::directory_options::skip_permission_denied;

                    for (const auto& entry : std::filesystem::recursive_directory_iterator(path, dir_opt))
                    {
                        const auto eas = file.ReadEa(entry.path(), eaConf_.EaName);
                        eaPrinter_.PrintEas(entry.path(), eas);
                    }
                }
                else
                {
                    const auto eas = file.ReadEa(f, eaConf_.EaName);
                    eaPrinter_.PrintEas(path, eas);
                }
            }
            else
            {
                const auto eas = file.ReadEa(f, eaConf_.EaName);
                eaPrinter_.PrintEas(path, eas);
            }
        }
    }

    void ExcecuteWrite()
    {
        NativeFile file;
        for (const auto& f : eaConf_.Files)
        {
            if (!file.WriteEa(f, eaConf_) && !eaConf_.KeepGoing)
            {
                g_pgm->Exit(1, L"Failed to write EA to file: " + f);
                // unreachable
            }
        }
    }

    void ExcecuteDelete()
    {
        NativeFile file;
        for (const auto& f : eaConf_.Files)
        {
            if (!file.DeleteEa(f, eaConf_.EaName) && !eaConf_.KeepGoing)
            {
                g_pgm->Exit(1, L"Failed to delete EA in file: " + f);
                // unreachable
            }
        }
    }
    void ExcecuteClear()
    {
        // Delete all EAs on-by-one.

        NativeFile file;
        for (const auto& f : eaConf_.Files)
        {
            if (!file.ClearEa(f) && !eaConf_.KeepGoing)
            {
                g_pgm->Exit(1, L"Failed to clear all EA in file: " + f);
                // unreachable
            }
        }
    }

    EaConf    eaConf_;
    EaPrinter eaPrinter_ {eaConf_};
};

void worker(const int argc, const wchar_t* const* const argv)
{
    argh::parser cmdl;
    cmdl.parse(
        WideArgv(argc, argv)(), argh::parser::PREFER_FLAG_FOR_UNREG_OPTION | argh::parser::SINGLE_DASH_IS_MULTIFLAG);

    if (cmdl[{"-h", "--help"}])
    {
        g_pgm->Usage();
        g_pgm->Exit();
    }

    EaConf eaConf;
    if (!eaConf.Parse(cmdl))
    {
        g_pgm->Usage();
        g_pgm->Exit(1, L"Invalid arguments");
        // unreachable
    }

    EaWorker eaWorker(eaConf);
    eaWorker.Exceute();
}

int wmain(const int argc, const wchar_t* const* const argv)
{
    if (argc == 0)
        std::abort();

    g_pgm = std::make_unique<Program>("xattr");

    try
    {
        worker(argc, argv);
    }
    catch (const ExitProgram& e)
    {
        std::exit(e.code);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "Unknown error" << std::endl;
    }

    return 0;
}
