#include "pch.h"

#include "argh.h"           // https://github.com/adishavit/argh
#include <colorconsole.hpp> // https://github.com/aafulei/color-console

#pragma comment(lib, "ntdll")

// Set and restore the console codepage to UTF-8.
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

// Thrown by Program::Exit() to terminate the program with a specific exit code.
class ExitProgram : public std::exception
{
public:
    int code;
    ExitProgram(int code) : code(code)
    {
    }
};

// Control livetime of the program and cleanup.
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
        std::cout << R"(
Similar to the commands of the Linux xattr, the following arguments may be supplied:

List only the names of all EAs on the given file(s):
```
xattr [-eklrvx] file [ file ... ]
```
Print only the value of EA ea_name on the given file(s):
```
xattr -p [-eklrvx] ea_name file [ file ... ]
```
Write the value of the EA ea_name to ea_value:
```
xattr -w [-fkrux] ea_name ea_value file [ file ... ]
    (No output on success, error messages on stderr.)
```
Delete the EA ea_name from file(s):
```
xattr -d [-kr] ea_name file [ file ... ]
    (No output on success, error messages on stderr.)
```
Clear all EA from the given file(s):
```
xattr -c [-kr] file [ file ... ]
    (No output on success, error messages on stderr.)
```
Options:

    -c  Clear all Attributes.

    -d  Delete the given attribute.

    -e  Expand / extract / examine well known EAs.

    -f  Write content of a given file as EA value. Max size is 65565 bytes.
        Use with -w option. This option can not be combined with -x or -u.

    -h  Help.

    -k  Keep-going. Ignore errors and continue processing the next file. 
        This is useful when you want to process a list of files and ignore errors on some of them.

    -l  By default, the first two command forms either display just the attribute names or
        values, respectively. The -l option causes both the attribute names and corresponding
        values to be displayed. For hex display of values, the output is preceeded with the hex
        offset values and followed by ASCII display, enclosed by '|'.

    -m  Max-depth for recursive processing. Default is 1. 
        0 => only the given directory, 
        1 => only the files in the given directory, 
        2 => files in the given directory and their subdirectories, etc.
        This option is only valid with -r option.

    -p  Print the value associated with the given attribute.

    -r  If a file argument is a directory, act as if the entire contents of the directory
        recursively were also specified (so that every file in the directory tree is acted upon).

    -u  Write value as unicode string (UTF-16LE). The Default is UTF-8. 
        This option can not be combined with -x.

    -v  View the file name, even for a single file.

    -w  Write a given attribute name with a value.

    -x  Force the attribute value to be displayed in the hexadecimal representation.
        This option can not be combined with -u.

    --debug  Print debug information to stdout.

One or more files or directories may be specified on the command line.

For the first two forms of the command, if there is more than one file, 
the file name is displayed along with the actual results. 
When only one file is specified, the display of the file name is suppressed unless the -v option, is also specified.

Attribute values are usually displayed as strings. However, if unprintable data are detected, the value is displayed in a hexadecimal representation.

The -w option normally assumes the input attribute value is a string. 
Specifying the -x option causes xattr to expect the input in hexadecimal (whitespace is ignored). 
The hex bytes must be enclosed in "".

xattr exits with 0 on success.
On error it exits with a non-zero value and prints an error message on stderr.
)";
    }

private:
    std::string               name_;
    std::unique_ptr<Codepage> codepage_;
    bool                      exited_ {false};
    bool                      inCtor_ {false};
};

std::unique_ptr<Program> g_pgm;
bool                     g_debug {false};

// Takes wide argv parameter from wmain() and converts it to UTF-8 argv.
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
    // Give argv as UTF-8
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

// Semantically parsed commandline parameters.
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
        if (cmdl[{"-p"}])
        {
            if (cmdl.pos_args().size() < 2)
            {
                g_pgm->Exit(1, L"EA name and file(s) are required.");
                // unreachable
                return false;
            }
            Command        = Cmd::Print;
            EaName         = cmdl[0];
            firstFileIndex = 1;
        }
        // Write the value of the EA ea_name to ea_value:
        // xattr -w[-rux] ea_name ea_value file [ file ... ]
        else if (cmdl[{"-w"}])
        {
            if (cmdl.pos_args().size() < 3)
            {
                g_pgm->Exit(1, L"EA name, value and file(s) are required.");
                // unreachable
                return false;
            }
            Command        = Cmd::Write;
            EaName         = cmdl[0];
            EaValue        = cmdl[1];
            firstFileIndex = 2;
        }
        // Delete the EA ea_name from file(s):
        // xattr -d[-rv] ea_name file [ file ... ]
        else if (cmdl[{"-d"}])
        {
            if (cmdl.pos_args().size() < 2)
            {
                g_pgm->Exit(1, L"EA name and file(s) are required.");
                // unreachable
                return false;
            }
            Command        = Cmd::Delete;
            EaName         = cmdl[0];
            firstFileIndex = 1;
        }
        // Clear all EA from the given file(s):
        // xattr -c[-rv] file [ file ... ]
        else if (cmdl[{"-c"}])
        {
            if (cmdl.pos_args().size() < 1)
            {
                g_pgm->Exit(1, L"File(s) are required.");
                // unreachable
                return false;
            }
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

            Expand        = cmdl[{"-e"}];
            Hex           = cmdl[{"-x"}];
            KeepGoing     = cmdl[{"-k"}];
            Long          = cmdl[{"-l"}];
            Recursive     = cmdl[{"-r"}];
            Unicode       = cmdl[{"-u"}];
            ValueFromFile = cmdl[{"-f"}];
            ViewFile      = cmdl[{"-v"}];

            cmdl("m", 1) >> MaxDepth;
        }

        return Command != Cmd::Invalid;
    }

    Cmd Command {Cmd::Invalid};
    // 8-bit ASCII, excluding invalid EA chars 0x00 - 0x1F, \ / : * ? " < > | , + = [ ] ;
    std::string EaName;
    std::string EaValue;

    bool Expand {false};
    bool Hex {false};
    bool KeepGoing {false};
    bool Long {false};
    bool Recursive {false};
    bool Unicode {false};
    bool ValueFromFile {false};
    bool ViewFile {false};

    int MaxDepth {1};

    std::vector<std::wstring> Files;
};

// Dump byte array to stdout in hex and ASCII format.
static void PrintHex(const std::vector<BYTE>& data, bool leadingNewline)
{
    const size_t bytesPerLine = 16;

    if (leadingNewline)
        std::cout << std::endl;

    for (size_t offset = 0; offset < data.size(); offset += bytesPerLine)
    {
        // Offset (4-digit hex, padded)
        std::cout << std::setw(4) << std::setfill('0') << std::hex << offset << ":  ";

        // First 16 bytes as hex
        for (size_t i = 0; i < bytesPerLine; ++i)
        {
            if (offset + i < data.size())
                std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[offset + i]) << " ";
            else
                std::cout << "   ";

            if (i == 7)
                std::cout << " ";
        }

        std::cout << " ";

        // ASCII representation
        for (size_t i = 0; i < bytesPerLine; ++i)
        {
            if (offset + i < data.size())
            {
                BYTE ch = data[offset + i];
                std::cout << (std::isprint(ch) ? static_cast<char>(ch) : '.');
            }
            else
            {
                std::cout << ' ';
            }
        }

        std::cout << std::endl;
    }
}

// Wraps any native file operations and represents a file handle.
class NativeFile
{
public:
    NativeFile() = default;

    ~NativeFile()
    {
        if (hFile_ != INVALID_HANDLE_VALUE)
            NtClose(hFile_);
    }

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

    bool WriteEa(const std::wstring& file, const EaConf& eaConf)
    {
        if (eaConf.EaName.length() == 0 || eaConf.EaName.length() > MAX_EA_NAME_LENGTH)
            return false;

        if (!eaConf.Hex && eaConf.EaValue.length() + 1 > MAX_EA_VALUE_BYTES)
            return false;

        std::vector<BYTE> bytes;
        if (eaConf.Hex)
        {
            bytes = ParseHexValue(eaConf.EaValue, MAX_EA_VALUE_BYTES);
            if (bytes.empty() || bytes.size() > MAX_EA_VALUE_BYTES)
                return false;
        }
        else if (eaConf.Unicode)
        {
            bytes.resize((eaConf.EaValue.length() + 1) * sizeof(WCHAR));
            std::copy(eaConf.EaValue.begin(), eaConf.EaValue.end(), (WCHAR*)bytes.data());
        }
        else if (eaConf.ValueFromFile)
        {
            // Read at most MAX_EA_VALUE_BYTES bytes from file whose name is stored in EaValue.
            auto f = CanonicalPath(UTF8ToWide(eaConf.EaValue));

            HANDLE hFile = CreateFileW(
                f.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (hFile == INVALID_HANDLE_VALUE)
                return false;

            LARGE_INTEGER fileSize {};
            if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > MAX_EA_VALUE_BYTES)
            {
                CloseHandle(hFile);
                return false;
            }

            bytes.resize(fileSize.LowPart);
            DWORD bytesRead = 0;

            if (!ReadFile(hFile, bytes.data(), fileSize.LowPart, &bytesRead, nullptr) || bytesRead != fileSize.LowPart)
            {
                CloseHandle(hFile);
                return false;
            }

            CloseHandle(hFile);
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
        if (g_debug)
        {
            std::cout << hue::yellow << "Prep ZwSetEaFile FILE_FULL_EA_INFORMATION size  "
                      << sizeof(FILE_FULL_EA_INFORMATION) << std::endl;
            std::cout << "Prep ZwSetEaFile EaName " << eaConf.EaName << std::endl;
            std::cout << "Prep ZwSetEaFile EaName len " << eaConf.EaName.length() << std::endl;
            std::cout << "Prep ZwSetEaFile bytes size " << bytes.size() << std::endl;
            PrintHex(bytes, false);
            std::cout << hue::reset;
        }
        std::vector<BYTE> buffer(sizeof(FILE_FULL_EA_INFORMATION) + eaConf.EaName.length() + bytes.size());
        auto              info = (PFILE_FULL_EA_INFORMATION)buffer.data();

        info->EaNameLength  = (UCHAR)eaConf.EaName.length();
        info->EaValueLength = (USHORT)bytes.size();
        strcpy_s(info->EaName, eaConf.EaName.length() + 1, eaConf.EaName.c_str());
        memcpy_s((PVOID)(info->EaName + info->EaNameLength + 1), info->EaValueLength, bytes.data(), bytes.size());

        if (g_debug)
        {
            std::cout << hue::yellow << "Prep ZwSetEaFile buffer size " << buffer.size() << std::endl;
            PrintHex(buffer, false);
            std::cout << hue::reset;
        }

        IO_STATUS_BLOCK ioStatus {};
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwseteafile
        NTSTATUS status = ZwSetEaFile(hFile_, &ioStatus, info, (ULONG)buffer.size());

        if (g_debug && !NT_SUCCESS(status))
        {
            std::cout << hue::yellow << "ZwSetEaFile failed with " << std::hex << status << std::endl;

            ULONG errorOffset = 0;
            // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iocheckeabuffervalidity
            NTSTATUS stat =
                IoCheckEaBufferValidity((PFILE_FULL_EA_INFORMATION)info, (ULONG)buffer.size(), &errorOffset);
            if (!NT_SUCCESS(stat))
            {
                std::cout << "IoCheckEaBufferValidity failed with " << std::hex << stat << std::endl;
                std::cout << "IoCheckEaBufferValidity errorOffset " << errorOffset << std::endl;
            }
            std::cout << hue::reset;
        }
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
        if (g_debug && !NT_SUCCESS(status))
        {
            std::cout << hue::yellow << "ZwSetEaFile failed with " << std::hex << status << hue::reset << std::endl;
        }
        return !!NT_SUCCESS(status);
    }

    // Delete all EAs on-by-one.
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
        {
            if (file_ != file)
                g_pgm->Exit(1, L"File handle already open for another file. Program logic issue...");
            return true;
        }

        auto f = CanonicalPath(file);

        UNICODE_STRING name {};
        RtlInitUnicodeString(&name, f.c_str());

        OBJECT_ATTRIBUTES attr = RTL_CONSTANT_OBJECT_ATTRIBUTES(&name, 0);
        IO_STATUS_BLOCK   ioStatus {};

        NTSTATUS status = NtOpenFile(&hFile_, (write ? (FILE_WRITE_EA | FILE_READ_EA) : FILE_READ_EA) | SYNCHRONIZE,
            &attr, &ioStatus, FILE_SHARE_WRITE | FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
        if (g_debug && !NT_SUCCESS(status))
        {
            std::cout << hue::yellow << "NtOpenFile failed with " << std::hex << status << hue::reset << std::endl;
        }

        if (NT_SUCCESS(status))
            file_ = file;

        return !!NT_SUCCESS(status);
    }

// IoCheckEaBufferValidity from ReactOS
// https://doxygen.reactos.org/dd/dca/ntoskrnl_2io_2iomgr_2util_8c.html#afe2c3c43295f280b2452f0111e32b452
// https://doxygen.reactos.org/d0/d2d/GetWindowPlacement_8c_source.html
#define ALIGN_DOWN_BY(size, align) ((ULONG_PTR)(size) & ~((ULONG_PTR)(align) - 1))
#define ALIGN_UP_BY(size, align) (ALIGN_DOWN_BY(((ULONG_PTR)(size) + align - 1), align))

    NTSTATUS
    NTAPI
    IoCheckEaBufferValidity(IN PFILE_FULL_EA_INFORMATION EaBuffer, IN ULONG EaLength, OUT PULONG ErrorOffset)
    {
        ULONG                     NextEntryOffset;
        UCHAR                     EaNameLength;
        ULONG                     ComputedLength;
        PFILE_FULL_EA_INFORMATION Current;

        /* We will browse all the entries */
        for (Current = EaBuffer;; Current = (PFILE_FULL_EA_INFORMATION)((ULONG_PTR)Current + NextEntryOffset))
        {
            /* Check that we have enough bits left for the current entry */
            if (EaLength < FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName))
            {
                goto FailPath;
            }

            EaNameLength   = Current->EaNameLength;
            ComputedLength = Current->EaValueLength + EaNameLength + FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + 1;
            /* Check that we have enough bits left for storing the name and its value */
            if (EaLength < ComputedLength)
            {
                goto FailPath;
            }

            /* Make sure the name is null terminated */
            if (Current->EaName[EaNameLength] != ANSI_NULL)
            {
                goto FailPath;
            }

            /* Get the next entry offset */
            NextEntryOffset = Current->NextEntryOffset;
            /* If it's 0, it's a termination case */
            if (NextEntryOffset == 0)
            {
                /* If we don't overflow! */
                if ((LONG)(EaLength - ComputedLength) < 0)
                {
                    goto FailPath;
                }

                break;
            }

            /* Compare the next offset we computed with the provided one, they must match */
            if (ALIGN_UP_BY(ComputedLength, sizeof(ULONG)) != NextEntryOffset)
            {
                goto FailPath;
            }

            /* Check next entry offset value is positive */
            if ((LONG)NextEntryOffset < 0)
            {
                goto FailPath;
            }

            /* Compute the remaining bits */
            EaLength -= NextEntryOffset;
            /* We must have bits left */
            if ((LONG)EaLength < 0)
            {
                goto FailPath;
            }

            /* Move to the next entry */
        }

        /* If we end here, everything went OK */
        return STATUS_SUCCESS;

    FailPath:
        /* If we end here, we failed, set failed offset */
        *ErrorOffset = (ULONG)((ULONG_PTR)Current - (ULONG_PTR)EaBuffer);
        return STATUS_EA_LIST_INCONSISTENT;
    }

    HANDLE       hFile_ {INVALID_HANDLE_VALUE};
    std::wstring file_;
};

// Prints given EAs to the console respecting the commandline options.
class EaPrinter
{
public:
    EaPrinter(const EaConf& eaConf) : eaConf_(eaConf)
    {
    }

    void PrintEas(std::filesystem::path path, const std::vector<std::pair<std::string, std::vector<BYTE>>>& eas)
    {
        if (eas.empty())
            return;

        bool         printFile = eaConf_.ViewFile || eaConf_.Recursive || eaConf_.Files.size() > 1;
        std::wstring filename;

        if (printFile)
            filename = path.wstring();

        bool printName  = eaConf_.Command == EaConf::Cmd::List || eaConf_.Long;
        bool printValue = eaConf_.Command == EaConf::Cmd::Print || eaConf_.Long;

        for (const auto& ea : eas)
        {
            if (printFile)
                std::wcout << filename << L": ";

            if (printName)
            {
                // Explicitly use the wide string output stream to avoid any conversion issues
                // as the EA name is ASCII, not UTF-8.
                std::wcout << AsciiToWide(ea.first);
            }

            if (printValue)
            {
                if (printName)
                    std::cout << ": ";

                // Expand well-known EAs
                if (eaConf_.Expand && ea.first == "$CI.CATALOGHINT" && ea.second.size() > 4)
                {
                    // clang-format off
                    /*
                    * Sample from ntdll.dll
0000:  01 00 5a 00 4d 69 63 72  6f 73 6f 66 74 2d 57 69  ..Z.Microsoft-Wi
0010:  6e 64 6f 77 73 2d 4b 65  72 6e 65 6c 2d 50 61 63  ndows-Kernel-Pac
0020:  6b 61 67 65 2d 4e 74 64  6c 6c 2d 50 61 63 6b 61  kage-Ntdll-Packa
0030:  67 65 7e 33 31 62 66 33  38 35 36 61 64 33 36 34  ge~31bf3856ad364
0040:  65 33 35 7e 61 6d 64 36  34 7e 7e 31 30 2e 30 2e  e35~amd64~~10.0.
0050:  32 36 31 30 30 2e 33 33  32 33 2e 63 61 74        26100.3323.cat
                    */
                    // clang-format on

                    // No idea what the first 4 bytes are, but the rest is a catalog file name to speed up signature lookup.
                    DWORD d = *(DWORD*)ea.second.data();
                    std::cout << std::hex << d << " " << std::string((char*)ea.second.data() + 4, ea.second.size() - 4);
                }
                else if (eaConf_.Hex || AnyNonPrintable(ea.second))
                {
                    PrintHex(ea.second, printName);
                }
                else if (eaConf_.Unicode)
                {
                    std::wcout << std::wstring((wchar_t*)ea.second.data(), ea.second.size() / 2);
                }
                else
                {
                    std::cout << std::string((char*)ea.second.data(), ea.second.size());
                }
            }
            std::cout << std::endl;
        }
    }

private:
    bool AnyNonPrintable(const std::vector<BYTE>& bytes, int startOffset = 0)
    {
        if (startOffset >= (int)bytes.size())
            return false;

        if (eaConf_.Unicode)
        {
            // A possible valid wide string shall be even in size and at least 4 bytes long.
            if (bytes.size() % 2 != 0 || bytes.size() < 4)
                true;

            // Shall end in a 0 termination.
            if (bytes[bytes.size() - 2] != 0 || bytes[bytes.size() - 1] != 0)
                return true;

            // Exclude the terminating 0
            for (size_t i = 0; i < bytes.size() - 2; i += 2)
            {
                wchar_t c = *(wchar_t*)&bytes[i];
                if (!iswprint(c))
                    return true;
            }
        }
        else
        {
            // A possible valid narrow string shall be at least 2 bytes long.
            if (bytes.size() < 2)
                true;

            // Shall end in a 0 termination.
            if (bytes[bytes.size() - 1] != 0)
                return true;

            // Exclude the terminating 0
            for (size_t i = 0; i < bytes.size() - 1; ++i)
            {
                BYTE c = bytes[i];
                if (!isprint(c))
                    return true;
            }
        }

        return false;
    }
    EaConf eaConf_;
};

// Executes commands based on the parsed commandline parameters.
class EaWorker
{
public:
    EaWorker(const EaConf& eaConf) : eaConf_(eaConf)
    {
    }

    void Exceute()
    {
        for (const auto& f : eaConf_.Files)
        {
            auto            path = std::filesystem::path(f);
            std::error_code ec;

            if (std::filesystem::is_directory(path, ec) && !ec)
            {
                if (eaConf_.Recursive)
                {
                    const std::filesystem::directory_options dir_opt =
                        std::filesystem::directory_options::skip_permission_denied;

                    for (auto it = std::filesystem::recursive_directory_iterator(path, dir_opt);
                        it != std::filesystem::recursive_directory_iterator(); ++it)
                    {
                        if (it->is_directory(ec) && !ec)
                        {
                            if (g_debug)
                            {
                                std::cout << hue::yellow << std::string(it.depth(), ' ') << it.depth() << " : "
                                          << WideToUTF8(it->path().wstring()) << hue::reset << std::endl;
                            }
                            if (it.depth() >= eaConf_.MaxDepth)
                                it.disable_recursion_pending(); // don't recursively enter this directory
                        }
                        else if (it->is_regular_file(ec) && !ec)
                        {
                            if (g_debug)
                            {
                                std::cout << hue::green << std::string(it.depth(), ' ') << it.depth() << " : "
                                          << WideToUTF8(it->path().wstring()) << hue::reset << std::endl;
                            }
                            // Certain paths like e.g. C:\Windows\MEMORY.DMP are failing the relative() call.
                            // So call relative() first and don't ReadEa(), as it probably will fail anyhow.
                            auto relative_path = std::filesystem::relative(it->path(), path, ec);
                            if (!ec)
                            {
                                if (!ExceuteCommand(it->path().wstring(), relative_path) && !eaConf_.KeepGoing)
                                {
                                    g_pgm->Exit(1, L"Failed to excecute command on file: " + it->path().wstring());
                                    // unreachable
                                }
                            }
                            else
                            {
                                if (g_debug)
                                {
                                    std::cout << hue::red << std::string(it.depth(), ' ')
                                              << "Failed to get relative path: " << ec << hue::reset << std::endl;
                                }
                            }
                        }
                    }
                }
                else
                {
                    if (!ExceuteCommand(f, path) && !eaConf_.KeepGoing)
                    {
                        g_pgm->Exit(1, L"Failed to excecute command on directory: " + f);
                        // unreachable
                    }
                }
            }
            else
            {
                if (!ExceuteCommand(f, path) && !eaConf_.KeepGoing)
                {
                    g_pgm->Exit(1, L"Failed to excecute command on file: " + f);
                    // unreachable
                }
            }
        }
    }

private:
    bool ExceuteCommand(const std::wstring& path, const std::filesystem::path& displayPath)
    {
        switch (eaConf_.Command)
        {
            case EaConf::Cmd::List:
            {
                NativeFile file;
                const auto eas = file.ReadEa(path, eaConf_.EaName);
                eaPrinter_.PrintEas(displayPath, eas);
                return true;
            }
            case EaConf::Cmd::Print:
            {
                NativeFile file;
                const auto eas = file.ReadEa(path, eaConf_.EaName);
                eaPrinter_.PrintEas(displayPath, eas);
                return true;
            }
            case EaConf::Cmd::Write:
            {
                NativeFile file;
                return file.WriteEa(path, eaConf_);
            }
            case EaConf::Cmd::Delete:
            {
                NativeFile file;
                return file.DeleteEa(path, eaConf_.EaName);
            }
            case EaConf::Cmd::Clear:
            {
                NativeFile file;
                return file.ClearEa(path);
            }
            default:
                break;
        }
        return false;
    }

    EaConf    eaConf_;
    EaPrinter eaPrinter_ {eaConf_};
};

void worker(const int argc, const wchar_t* const* const argv)
{
    argh::parser cmdl;
    cmdl.parse(
        WideArgv(argc, argv)(), argh::parser::PREFER_FLAG_FOR_UNREG_OPTION | argh::parser::SINGLE_DASH_IS_MULTIFLAG);

    g_debug = cmdl[{"--debug"}];

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
        std::cerr << hue::red << "Error: " << e.what() << hue::reset << std::endl;
    }
    catch (...)
    {
        std::cerr << hue::red << "Unknown error" << hue::reset << std::endl;
    }

    return 0;
}
