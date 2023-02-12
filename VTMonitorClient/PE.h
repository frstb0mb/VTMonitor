#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <memory>

std::unique_ptr<BYTE[]> LoadPE(LPCWSTR path, DWORD &entry, PRUNTIME_FUNCTION &functables);