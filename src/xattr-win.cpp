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

class Program
{
public:
    Program(const std::string_view name) : name_(name)
    {
        codepage_ = std::make_unique<Codepage>();
    }
    ~Program()
    {
        Exit(0);
    }

    void Exit(const int exit_code = 0, const std::string_view msg = "")
    {
        if (exited_)
            return;

        exited_ = true;

        if (exit_code)
            std::cerr << name_ << " exited with code " << exit_code << " " << msg << std::endl;

        fflush(nullptr);
        codepage_.reset();

        std::exit(exit_code);
    }

    void Usage()
    {
    }

private:
    std::string               name_;
    std::unique_ptr<Codepage> codepage_;
    bool                      exited_ {false};
};

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
    EaConf(const argh::parser& cmdl)
    {
        int firstFileIndex = 0;
        // Print value of EA ea_name on the given file(s):
        // xattr -p[-lrvx] ea_name file[file...]
        if (cmdl[{"-p"}] && cmdl.pos_args().size() >= 2)
        {
            Command        = Cmd::Print;
            EaName         = UTF8ToWide(cmdl[0]);
            firstFileIndex = 1;
        }

        // Write the value of the EA ea_name to attr_value:
        // xattr -w[-rx] ea_name ea_value file[file...]
        if (cmdl[{"-w"}] && cmdl.pos_args().size() >= 3)
        {
            Command        = Cmd::Write;
            EaName         = UTF8ToWide(cmdl[0]);
            EaValue        = UTF8ToWide(cmdl[1]);
            firstFileIndex = 2;
        }

        // Delete the EA ea_name from file(s):
        // xattr -d[-rv] ea_name file[file...]
        if (cmdl[{"-d"}] && cmdl.pos_args().size() >= 2)
        {
            Command        = Cmd::Delete;
            EaName         = UTF8ToWide(cmdl[0]);
            firstFileIndex = 1;
        }

        // Clear all EA from the given file(s):
        // xattr -c[-rv] file[file...]
        if (cmdl[{"-c"}] && cmdl.pos_args().size() >= 1)
        {
            Command = Cmd::Clear;
        }

        // List only the names of all EAs on the given file(s):
        // xattr [-lrvx] file[file...]
        if (cmdl.pos_args().size() >= 1)
        {
            Command = Cmd::List;
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
        }
    }
    Cmd                       Command {Cmd::Invalid};
    std::wstring              EaName;
    std::wstring              EaValue;
    std::vector<std::wstring> Files;
    bool                      Long {false};
    bool                      Recursive {false};
    bool                      ViewFile {false};
    bool                      Hex {false};
};

std::unique_ptr<Program> g_pgm;

int wmain(const int argc, const wchar_t* const* const argv)
{
    if (argc == 0)
        std::abort();

    g_pgm = std::make_unique<Program>("xattr");

    argh::parser cmdl;
    cmdl.parse(
        WideArgv(argc, argv)(), argh::parser::PREFER_FLAG_FOR_UNREG_OPTION | argh::parser::SINGLE_DASH_IS_MULTIFLAG);

    if (cmdl[{"-h", "--help"}])
    {
        g_pgm->Usage();
        g_pgm->Exit();
    }

    EaConf eaConf(cmdl);

    if (eaConf.Command == EaConf::Cmd::Invalid)
    {
        g_pgm->Usage();
        g_pgm->Exit(1, "Invalid arguments");
    }

    g_pgm->Exit();

    // This line is never reached.
    return 0;
}
