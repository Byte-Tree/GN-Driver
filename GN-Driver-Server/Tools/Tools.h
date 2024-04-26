#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <codecvt> // codecvt_utf8
#include <locale>  // wstring_convert
#include <sstream>
#include <fstream>
#include <vector>


typedef void (WINAPI* fpnRtlGetNtVersionNumbers)(DWORD*, DWORD*, DWORD*);

typedef struct _systime
{
	int year; int month; int day; int hour; int min; int sec;
}systime;


class Tools
{
private:

public:
	Tools();
	~Tools();

public:
	std::string ToHexString(std::string s);
	std::string ToHexString(unsigned char* s, size_t len);
	std::string NumberToHexString(void* i, unsigned int len);
	std::string ToBytes(void* data, unsigned int len);
	std::wstring StringToWString(const std::string& str);
	std::string WStringToString(std::wstring& wide_string);

public:
	//将下标为startIndex开始，长度为length的这段数据进行大小端转换
	virtual unsigned char* EndianSwap(unsigned char* pData, int startIndex, int length);
	virtual unsigned int* SmallToBig(unsigned int* value);

public:
	virtual bool ReadFileToMemory(std::string file_path, std::string* p_buffer, unsigned long long read_offset = 0, unsigned long long read_len = 0, int mode = std::ios::in | std::ios::binary);
	virtual bool WriteMemoryToFile(std::string file_path, std::string buffer, int mode = std::ios::out | std::ios::binary);
	virtual bool CreateFile_(std::string file_path, int mode = std::ios::in | std::ios::out);

public:
	systime GetSystemTime();
	std::string GetSystemInfo();

};

