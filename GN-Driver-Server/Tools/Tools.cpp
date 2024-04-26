#include "Tools.h"


Tools::Tools()
{
}

Tools::~Tools()
{
}

std::string Tools::ToHexString(std::string s)
{
	std::ostringstream out;

	out << std::hex << std::setw(2) << std::setfill('0');
	for (size_t i = 0; i < s.size(); i++)
		out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>((unsigned char)s.data()[i]);

	return out.str();
}

std::string Tools::ToHexString(unsigned char* s, size_t len)
{
	std::ostringstream out;

	out << std::hex << std::setw(2) << std::setfill('0');
	for (size_t i = 0; i < len; i++)
		out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(s[i]);

	return out.str();
}

std::string Tools::NumberToHexString(void* i, unsigned int len)
{
	std::stringstream stream;

	stream << std::setfill('0') << std::setw(len * 2)
		<< std::hex << i;

	return stream.str();
}

std::string Tools::ToBytes(void* data, unsigned int len)
{
	std::string stringb;
	char* bytes = new char[len];

	memcpy(bytes, &data, len);
	stringb.append(bytes, len);

	bytes = nullptr;
	delete[] bytes;

	return stringb;
}

std::wstring Tools::StringToWString(const std::string& str)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.from_bytes(str);
}

std::string Tools::WStringToString(std::wstring& wide_string)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8_conv;
	return utf8_conv.to_bytes(wide_string);
}

unsigned char* Tools::EndianSwap(unsigned char* pData, int startIndex, int length)
{
	int i, cnt, end, start;
	cnt = length / 2;
	start = startIndex;
	end = startIndex + length - 1;
	unsigned char tmp;

	for (i = 0; i < cnt; i++)
	{
		tmp = pData[start + i];
		pData[start + i] = pData[end - i];
		pData[end - i] = tmp;
	}

	return pData;
}

unsigned int* Tools::SmallToBig(unsigned int* value)
{
	char tmp = '\0';
	char* ptr = (char*)value;

	tmp = *ptr;
	*ptr = *(ptr + 3);
	*(ptr + 3) = tmp;
	tmp = *(ptr + 1);
	*(ptr + 1) = *(ptr + 2);
	*(ptr + 2) = tmp;

	return value;
}

bool Tools::ReadFileToMemory(std::string file_path, std::string* p_buffer, unsigned long long read_offset, unsigned long long read_len, int mode)
{
	std::ifstream file(file_path, mode);
	unsigned long long read_file_len = read_len;

	if (!file.is_open())
		return false;

	if (read_offset == 0)
	{
		//获取文件大小
		file.seekg(0, std::ifstream::end);
		read_file_len = file.tellg();
		file.seekg(0);
	}
	else
	{
		//根据想要读取的偏移获取对应长度数据
		file.seekg(read_offset, std::ios::beg);
	}

	//读取文件数据
	char* temp_buffer = new char[read_file_len];

	file.read(temp_buffer, read_file_len);
	p_buffer->append(temp_buffer, read_file_len);

	file.close();
	delete[] temp_buffer;

	return true;
}

bool Tools::WriteMemoryToFile(std::string file_path, std::string buffer, int mode)
{
	std::ofstream file(file_path, mode);

	if (!file.is_open())
		return false;

	//写入文件数据
	file.write(buffer.data(), buffer.size());
	file.close();

	return true;
}

bool Tools::CreateFile_(std::string file_path, int mode)
{
	std::fstream file(file_path, mode);

	if (!file.is_open())
		return false;

	file.close();

	return true;
}

systime Tools::GetSystemTime()
{
	time_t rawtime;
	tm* timeinfo;

	systime ret_time = { NULL };
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	ret_time.year = 1900 + timeinfo->tm_year;
	ret_time.month = 1 + timeinfo->tm_mon;
	ret_time.day = timeinfo->tm_mday;
	ret_time.hour = timeinfo->tm_hour;
	ret_time.min = timeinfo->tm_min;
	ret_time.sec = timeinfo->tm_sec;
	return ret_time;
}

std::string Tools::GetSystemInfo()
{
	std::string info;
	DWORD major, minor, build_number;
	HMODULE ntdll = ::LoadLibraryA("ntdll.dll");

	fpnRtlGetNtVersionNumbers pRtlGetNtVersionNumbers = (fpnRtlGetNtVersionNumbers)::GetProcAddress(ntdll, "RtlGetNtVersionNumbers");
	if (pRtlGetNtVersionNumbers)
	{
		pRtlGetNtVersionNumbers(&major, &minor, &build_number);
		build_number &= 0xFFFF;

		//std::cout << "major:" << major << std::endl;
		//std::cout << "minor:" << minor << std::endl;
		//std::cout << "build_number:" << build_number << std::endl;
		//system_version = MAKELONG(MAKEWORD(major, minor), build_number);

		info.append(std::to_string(major) + ".");
		info.append(std::to_string(minor) + ".");
		info.append(std::to_string(build_number));
	}
	//std::cout << "system_version: " << info << std::endl;

	return info;
}
