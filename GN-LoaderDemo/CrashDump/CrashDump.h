#pragma once

#include "../pch.h"
#include <Dbghelp.h>
#include <ctime>
#include <string>
#include <sstream>
#include <assert.h>
#include <shellapi.h>


class CrashDump 
{
private:
    LPTOP_LEVEL_EXCEPTION_FILTER m_oldExceptionFilter;

private:
    static LONG WINAPI UnhandledExceptionFilter(struct _EXCEPTION_POINTERS* pExceptionInfo);

public:
    explicit CrashDump();
    ~CrashDump();

};



