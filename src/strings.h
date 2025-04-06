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

