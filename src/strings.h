#pragma once
#include <string>

// Wide (UTF-16) -> UTF-8
inline std::string WideToUTF8(const std::wstring_view& wideStr)
{
    if (wideStr.empty())
        return {};

    int sizeRequired = WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), -1, nullptr, 0, nullptr, nullptr);
    if (sizeRequired <= 0)
        return {};

    std::string utf8Str(sizeRequired - 1, 0); // -1 to exclude null terminator
    WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), -1, &utf8Str[0], sizeRequired, nullptr, nullptr);

    return utf8Str;
}

// UTF-8 -> Wide (UTF-16)
inline std::wstring UTF8ToWide(const std::string_view& utf8Str)
{
    if (utf8Str.empty())
        return {};

    int sizeRequired = MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), -1, nullptr, 0);
    if (sizeRequired <= 0)
        return {};

    std::wstring wideStr(sizeRequired - 1, 0); // -1 to exclude null terminator
    MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), -1, &wideStr[0], sizeRequired);

    return wideStr;
}

inline std::string WideToAscii(const std::wstring_view& wideStr)
{
    std::string str;
    str.reserve(wideStr.size());
    for (const wchar_t wc : wideStr)
    {
        str.push_back(static_cast<char>(wc));
    }
    return str;
}

inline std::wstring AsciiToWide(const std::string_view& asciiStr)
{
    std::wstring str;
    str.reserve(asciiStr.size());
    for (const char c : asciiStr)
    {
        str.push_back(static_cast<wchar_t>(c));
    }
    return str;
}

inline std::string RemoveWhitespaces(const std::string& input)
{
    std::string result = input;
    result.erase(std::remove_if(result.begin(), result.end(), ::isspace), result.end());
    return result;
}

// Convert a hex string to a byte array, example input: "01 02 03" or "010203" or "aa AA aA Aa"
inline std::vector<BYTE> ParseHexValue(const std::string& value, size_t maxByteCount)
{
    std::string v = RemoveWhitespaces(value);

    if (v.length() % 2 != 0)
        return {};

    if (v.length() / 2 > maxByteCount)
        return {};

    std::vector<BYTE> bytes;
    bytes.reserve(v.length() / 2);
    for (size_t i = 0; i < v.length(); i += 2)
    {
        try
        {
            std::string s(v.data() + i, 2);
            BYTE        b = (BYTE)std::stoul(s, nullptr, 16);
            bytes.push_back(b);
        }
        catch (const std::exception&)
        {
            return {};
        }
    }
    return bytes;
}
