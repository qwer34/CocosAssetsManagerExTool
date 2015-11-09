#if defined(WIN32)

// Exclude rarely-used stuff from Windows headers
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif	//WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <io.h>

#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#else

#include <unistd.h>
#include <dirent.h>
#include <sys/param.h>

#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <condition_variable>

#include "cJSON/cJSON.h"
#include "MD5/md5.h"

#ifndef R_OK
#define R_OK		(4)		/* Test for read permission.  */
#endif

#ifndef W_OK
#define W_OK		(2)		/* Test for write permission.  */
#endif

#ifndef F_OK
#define F_OK		(0)		/* Test for existence.  */
#endif

#ifdef WIN32
#define PATH_SEPARATOR_CHAR				'\\'
#define PATH_SEPARATOR_STRING			"\\"
#else
#define PATH_SEPARATOR_CHAR				'/'
#define PATH_SEPARATOR_STRING			"/"
#endif

using namespace std;

//////////////////////////////////////////////////////////////////////////

#define EXEC_BINARY_NAME				"CocosAssetsManagerExTool"
#define EXEC_BINARY_VERSION				"0.0.2"
#define PROJECT_MANIFEST_FILENAME		"project.manifest"
#define VERSION_MANIFEST_FILENAME		"version.manifest"
#define DEFAULT_ENGINE_VERSION			"3.7"

enum class RETURN_VALUE
{
	OK = 0,
	SHOW_HELP,
	INCORRECT_ARGS,
	INCORRECT_URL,
	INCORRECT_VERSION,
	INCORRECT_ENGINE_VERSION,
	INCORRECT_OUTPUT_PATH,
	INCORRECT_RES_PATH,
	MANIFEST_WRITE_ERROR,
	UNKNOWN_ERROR = -1
};

#if defined(WIN32) && (defined(DEBUG) || defined(_DEBUG))
#define RETURN(__ret__)					{ getchar(); return (int)(__ret__); }
#else
#define RETURN(__ret__)					{ return (int)(__ret__); }
#endif

//////////////////////////////////////////////////////////////////////////

// 打印分隔用的星号
static void PrintLongGapLine(void)
{
	printf("************************************\r\n");
}

// 打印本程序版本信息
static void PrintVersion(void)
{
	printf("* %s  Ver. %s\r\n", EXEC_BINARY_NAME, EXEC_BINARY_VERSION);
	printf("* Powered by Xin Zhang\r\n");
	printf("* %s %s\r\n", __TIME__, __DATE__);
}

// 打印帮助信息
static void PrintHelp(void)
{
	printf("* ============\r\n");
	printf("* Usage:\r\n");
	printf("* ------\r\n");
	printf("* %s <options>\r\n", EXEC_BINARY_NAME);
	printf("*   --help                  Help (this text).\r\n");
	printf("*   -h                      Same as '--help'.\r\n");
	printf("*   /?                      Same as '--help'.\r\n");
	printf("*   -url URL                Root path of manifest files and resources. Must end with '/'.\r\n");
	printf("*   -u URL                  Same as '-url'.\r\n");
	printf("*   -version version        Version number, better using an integer.\r\n");
	printf("*   -v version              Same as '-version'.\r\n");
	printf("*   -engineversion version  Version string of the engine.\r\n");
	printf("*   -ev version             Same as '-engineversion'.\r\n");
	printf("*   -o path                 Output directory of manifest files. Resources should be placed in the subdirectory named of version.\r\n");
}

// 打印传入的参数
static void PrintArgs(int argc, char * argv[])
{
	if (argc > 1)
	{
		printf("* ============\r\n");
		printf("* Arguments:\r\n");
		printf("* ----------\r\n");

		for (int i = 1; i < argc; i++)
		{
			printf("* %d : %s\r\n", i, argv[i]);
		}
	}
}

// 计算MD5
static const string GetMd5OfFile(const string& strFilePath)
{
	const static string strFaultRet = "...";
	FILE * fileToRead = fopen(strFilePath.c_str(), "rb");

	if (!fileToRead)
	{
		printf("%s: fopen error.\r\n", __FUNCTION__);

		return strFaultRet;
	}

	int nFeekResult = fseek(fileToRead, 0, SEEK_END);
	long nFileSize = ftell(fileToRead);
	unsigned char * pBuffer = nullptr;

	if (0 != nFeekResult)
	{
		printf("%s: fseek error.\r\n", __FUNCTION__);
	}
	else if (nFileSize < 0)
	{
		printf("%s: ftell error.\r\n", __FUNCTION__);
	}
	else
	{
		if ((pBuffer = (unsigned char *)malloc(sizeof(unsigned char) * (nFileSize + 1))))
		{
			if (nFileSize)
			{
				fseek(fileToRead, 0, SEEK_SET);

				if (nFileSize == fread(pBuffer, sizeof(unsigned char), nFileSize, fileToRead))
				{
					pBuffer[nFileSize] = 0;
				}
				else
				{
					printf("%s: fread error.\r\n", __FUNCTION__);
					free(pBuffer);
					pBuffer = nullptr;
				}
			}
			else
			{
				// Empty file won't be read.
				pBuffer[0] = 0;
			}
		}
		else
		{
			printf("%s: malloc error.\r\n", __FUNCTION__);
		}
	}

	fclose(fileToRead);

	if (!pBuffer)
	{
		return strFaultRet;
	}

	static const char s_szDigits[] = "0123456789abcdef";
	char szMD5String[33];
	MD5_CTX context;

	MD5Init(&context);
	MD5Update(&context, pBuffer, (unsigned int)nFileSize);
	MD5Final(&context);

	for (size_t i = 0; i < sizeof(context.digest); i++)
	{
		unsigned char ucCurByte = context.digest[i];

		szMD5String[2 * i] = s_szDigits[ucCurByte >> 4];
		szMD5String[2 * i + 1] = s_szDigits[ucCurByte & 0xf];
	}

	szMD5String[32] = 0;

	free(pBuffer);
	pBuffer = nullptr;

	return string(szMD5String);
}

static void ParseDirectory(cJSON * const cJsonAssets, const string& strRootPath, const string& strRelativePath)
{
#ifdef WIN32

	string strFullPath = strRootPath + strRelativePath;
	string strToScan = strFullPath + "*.*";
	WIN32_FIND_DATAA FindFileData = { 0 };
	HANDLE hFind = ::FindFirstFileA(strToScan.c_str(), &FindFileData);

	if (INVALID_HANDLE_VALUE == hFind)
	{
		return;
	}

	while (TRUE)
	{
		if (FindFileData.cFileName[0] != '.')
		{
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				const string strSubDir = strRelativePath + FindFileData.cFileName + "/";
				ParseDirectory(cJsonAssets, strRootPath, strSubDir);
			}
			else
			{
				const string strSubFile = strRelativePath + FindFileData.cFileName;
				const string strSubFileFullPath = strFullPath + FindFileData.cFileName;
				const string strMD5 = GetMd5OfFile(strSubFileFullPath);
				cJSON * cJsonFile = cJSON_CreateObject();

				cJSON_AddItemToObject(cJsonFile, "md5", cJSON_CreateString(strMD5.c_str()));
				cJSON_AddItemToObject(cJsonAssets, strSubFile.c_str(), cJsonFile);
			}
		}

		if (!FindNextFileA(hFind, &FindFileData))
		{
			break;
		}
	}

	FindClose(hFind);

#else

	string strFullPath = strRootPath + strRelativePath;
	DIR * dir;
	struct dirent * entry;
	struct stat statbuf;

	if (!(dir = opendir(strFullPath.c_str())))
	{
		return;
	}

	while ((entry = readdir(dir)))
	{
		if ('.' == entry->d_name[0])
		{
			continue;
		}

		string strSub = strFullPath + entry->d_name;

		lstat(strSub.c_str(), &statbuf);

		if (S_ISDIR(statbuf.st_mode))
		{
			const string strSubDir = strRelativePath + entry->d_name + "/";
			ParseDirectory(cJsonAssets, strRootPath, strSubDir);
		}
		else
		{
			const string strSubFile = strRelativePath + entry->d_name;
			const string strMD5 = GetMd5OfFile(strSub);
			cJSON * cJsonFile = cJSON_CreateObject();

			cJSON_AddItemToObject(cJsonFile, "md5", cJSON_CreateString(strMD5.c_str()));
			cJSON_AddItemToObject(cJsonAssets, strSubFile.c_str(), cJsonFile);
		}
	}

	closedir(dir);

#endif
}

static bool WriteDataToFile(const string& strFilePath, const unsigned char * const pDataToWrite, const size_t nFileLength)
{
	FILE * fileToWrite = fopen(strFilePath.c_str(), "wb");

	if (!fileToWrite)
	{
		printf("%s: fopen error.\r\n", __FUNCTION__);

		return false;
	}

	//////////////////////////////////////////////////////////////////////////

	bool bRet = false;

	if (nFileLength && pDataToWrite)
	{
		if (nFileLength == fwrite(pDataToWrite, sizeof(char), nFileLength, fileToWrite))
		{
			bRet = true;
		}
		else
		{
			printf("%s: fwrite error.\r\n", __FUNCTION__);
		}
	}
	else
	{
		printf("%s: Nothing to write.\r\n", __FUNCTION__);
		bRet = true;
	}

	fclose(fileToWrite);

	return bRet;
}

// 入口函数
int main(int argc, char * argv[])
{
	bool bShouldPrintHelp = false;
	RETURN_VALUE nRet = RETURN_VALUE::OK;
	string strURL = "";
	string strVersion = "";
	string strEngineVersion = DEFAULT_ENGINE_VERSION;
	string strOutputPath = "." PATH_SEPARATOR_STRING;
	string strResPath;

	if (argc <= 1)
	{
		bShouldPrintHelp = true;
		nRet = RETURN_VALUE::SHOW_HELP;
	}
	else
	{
		for (int i = 1; i < argc; i++)
		{
			const char * szCurrentArg = argv[i];

			if (0 == strcmp("--help", szCurrentArg) ||
				0 == strcmp("-h", szCurrentArg) ||
				0 == strcmp("/?", szCurrentArg))
			{
				bShouldPrintHelp = true;
				nRet = RETURN_VALUE::SHOW_HELP;
				break;
			}
			else if (
				0 == strcmp("-url", szCurrentArg) ||
				0 == strcmp("-u", szCurrentArg))
			{
				if (i >= argc - 1)
				{
					bShouldPrintHelp = true;
					nRet = RETURN_VALUE::INCORRECT_ARGS;
					break;
				}
				else
				{
					szCurrentArg = argv[++i];

					if ('-' == szCurrentArg[0])
					{
						bShouldPrintHelp = true;
						nRet = RETURN_VALUE::INCORRECT_ARGS;
						break;
					}
					else
					{
						strURL = szCurrentArg;
						continue;
					}
				}
			}
			else if (
				0 == strcmp("-version", szCurrentArg) ||
				0 == strcmp("-v", szCurrentArg))
			{
				if (i >= argc - 1)
				{
					bShouldPrintHelp = true;
					nRet = RETURN_VALUE::INCORRECT_ARGS;
					break;
				}
				else
				{
					szCurrentArg = argv[++i];

					if ('-' == szCurrentArg[0])
					{
						bShouldPrintHelp = true;
						nRet = RETURN_VALUE::INCORRECT_ARGS;
						break;
					}
					else
					{
						strVersion = szCurrentArg;
						continue;
					}
				}
			}
			else if (
				0 == strcmp("-engineversion", szCurrentArg) ||
				0 == strcmp("-ev", szCurrentArg))
			{
				if (i >= argc - 1)
				{
					bShouldPrintHelp = true;
					nRet = RETURN_VALUE::INCORRECT_ARGS;
					break;
				}
				else
				{
					szCurrentArg = argv[++i];

					if ('-' == szCurrentArg[0])
					{
						bShouldPrintHelp = true;
						nRet = RETURN_VALUE::INCORRECT_ARGS;
						break;
					}
					else
					{
						strEngineVersion = szCurrentArg;
						continue;
					}
				}
			}
			else if (0 == strcmp("-o", szCurrentArg))
			{
				if (i >= argc - 1)
				{
					bShouldPrintHelp = true;
					nRet = RETURN_VALUE::INCORRECT_ARGS;
					break;
				}
				else
				{
					szCurrentArg = argv[++i];

					if ('-' == szCurrentArg[0])
					{
						bShouldPrintHelp = true;
						nRet = RETURN_VALUE::INCORRECT_ARGS;
						break;
					}
					else
					{
						strOutputPath = szCurrentArg;
						continue;
					}
				}
			}
			else
			{
				bShouldPrintHelp = true;
				nRet = RETURN_VALUE::INCORRECT_ARGS;
				break;
			}
		}
	}

	while (RETURN_VALUE::OK == nRet)
	{
		if (strURL.length() < 10 || 0 != memcmp("http", strURL.data(), sizeof("http") - 1))
		{
			bShouldPrintHelp = true;
			nRet = RETURN_VALUE::INCORRECT_URL;
			break;
		}
		else
		{
			char cLastChar = strURL[strURL.length() - 1];

			if ('/' != cLastChar)
			{
				strURL += '/';
			}
		}

		if (strVersion.length() < 1)
		{
			bShouldPrintHelp = true;
			nRet = RETURN_VALUE::INCORRECT_VERSION;
			break;
		}

		if (strEngineVersion.length() < 1)
		{
			bShouldPrintHelp = true;
			nRet = RETURN_VALUE::INCORRECT_ENGINE_VERSION;
			break;
		}

		if (strOutputPath.length() < 1)
		{
			strOutputPath = "." PATH_SEPARATOR_STRING;
		}
		else
		{
			char cLastChar = strOutputPath[strOutputPath.length() - 1];

			if (PATH_SEPARATOR_CHAR != cLastChar)
			{
				strOutputPath += PATH_SEPARATOR_STRING;
			}
		}

		if (-1 == access(strOutputPath.c_str(), R_OK))
		{
			bShouldPrintHelp = true;
			nRet = RETURN_VALUE::INCORRECT_OUTPUT_PATH;
			break;
		}

		strResPath = strOutputPath + strVersion;

		{
			char cLastChar = strResPath[strResPath.length() - 1];

			if (PATH_SEPARATOR_CHAR != cLastChar)
			{
				strResPath += PATH_SEPARATOR_STRING;
			}
		}

		if (-1 == access(strResPath.c_str(), R_OK))
		{
			bShouldPrintHelp = true;
			nRet = RETURN_VALUE::INCORRECT_RES_PATH;
			break;
		}

		break;
	}

	PrintLongGapLine();
	PrintVersion();

	if (bShouldPrintHelp)
	{
		PrintHelp();
	}

	PrintArgs(argc, argv);
	PrintLongGapLine();

	switch (nRet)
	{
	case RETURN_VALUE::INCORRECT_ARGS:
		printf("Incorrect args.\r\n");
		break;
	case RETURN_VALUE::INCORRECT_URL:
		printf("Incorrect URL format:\r\n%s\r\n", strURL.c_str());
		break;
	case RETURN_VALUE::INCORRECT_VERSION:
		printf("Incorrect version format:\r\n%s\r\n", strVersion.c_str());
		break;
	case RETURN_VALUE::INCORRECT_ENGINE_VERSION:
		printf("Incorrect engine version format:\r\n%s\r\n", strEngineVersion.c_str());
		break;
	case RETURN_VALUE::INCORRECT_OUTPUT_PATH:
		printf("The output path cannot be accessed:\r\n%s\r\n", strOutputPath.c_str());
		break;
	case RETURN_VALUE::INCORRECT_RES_PATH:
		printf("The resources path cannot be accessed:\r\n%s\r\n", strResPath.c_str());
		break;
	case RETURN_VALUE::UNKNOWN_ERROR:
		printf("Unknown error.\r\n");
		break;
	}

	if (RETURN_VALUE::OK != nRet)
	{
		RETURN(nRet);
	}

	cJSON * cJsonRoot = cJSON_CreateObject();
	string strProjectManifestFormatted;
	string strProjectManifestUnformatted;
	string strVersionManifestFormatted;
	string strVersionManifestUnformatted;

	// 生成工具信息 creator
	{
		char szCreatorInfo[64];

		sprintf(szCreatorInfo,
			"%s for %s Ver. %s",
			EXEC_BINARY_NAME,
#ifdef WIN32
			"Windows",
#else
			"OS X",
#endif
			EXEC_BINARY_VERSION);
		cJSON_AddItemToObject(cJsonRoot, "creator", cJSON_CreateString(szCreatorInfo));
	}

	// 生成时间 creationTime
	{
		char szLogFile[64];
		time_t rawtime;
		struct tm * timeinfo;
		time(&rawtime);
		timeinfo = localtime(&rawtime);

		sprintf(szLogFile,
			"%04d%02d%02d-%02d%02d%02d",
			timeinfo->tm_year + 1900,
			timeinfo->tm_mon + 1,
			timeinfo->tm_mday,
			timeinfo->tm_hour,
			timeinfo->tm_min,
			timeinfo->tm_sec);
		cJSON_AddItemToObject(cJsonRoot, "creationTime", cJSON_CreateString(szLogFile));
	}

	// packageUrl
	{
		string strPkgUrl = strURL + strVersion + "/";
		cJSON_AddItemToObject(cJsonRoot, "packageUrl", cJSON_CreateString(strPkgUrl.c_str()));
	}

	// remoteManifestUrl
	{
		string strRemoteManifestUrl = strURL + strVersion + "/" + PROJECT_MANIFEST_FILENAME;
		cJSON_AddItemToObject(cJsonRoot, "remoteManifestUrl", cJSON_CreateString(strRemoteManifestUrl.c_str()));
	}

	// remoteVersionUrl
	{
		string strRemoteVersionUrl = strURL + VERSION_MANIFEST_FILENAME;
		cJSON_AddItemToObject(cJsonRoot, "remoteVersionUrl", cJSON_CreateString(strRemoteVersionUrl.c_str()));
	}

	// version
	{
		cJSON_AddItemToObject(cJsonRoot, "version", cJSON_CreateString(strVersion.c_str()));
	}

	// engineVersion
	{
		cJSON_AddItemToObject(cJsonRoot, "engineVersion", cJSON_CreateString(strEngineVersion.c_str()));
	}

	strVersionManifestFormatted = cJSON_Print(cJsonRoot);
	strVersionManifestUnformatted = cJSON_PrintUnformatted(cJsonRoot);

	printf("%s\r\n\r\n", VERSION_MANIFEST_FILENAME);
	printf("%s\r\n", strVersionManifestFormatted.c_str());
	printf("============\r\n");

	// assets
	{
		cJSON * cJsonAssets = cJSON_CreateObject();

		ParseDirectory(cJsonAssets, strResPath, string(""));
		cJSON_AddItemToObject(cJsonRoot, "assets", cJsonAssets);
	}

	// searchPaths
	{
		cJSON_AddItemToObject(cJsonRoot, "searchPaths", cJSON_CreateArray());
	}

	strProjectManifestFormatted = cJSON_Print(cJsonRoot);
	strProjectManifestUnformatted = cJSON_PrintUnformatted(cJsonRoot);

	printf("%s\r\n\r\n", PROJECT_MANIFEST_FILENAME);
	printf("%s\r\n", strProjectManifestFormatted.c_str());
	printf("============\r\n");

	// 写入manifest文件
	{
		string strProjectManifestPath = strOutputPath + strVersion + PATH_SEPARATOR_STRING + PROJECT_MANIFEST_FILENAME;
		string strDeprecatedProjectManifestPath = strOutputPath + PROJECT_MANIFEST_FILENAME;
		string strVersionManifestPath = strOutputPath + VERSION_MANIFEST_FILENAME;

#if defined(DEBUG) || defined(_DEBUG)
		if (!WriteDataToFile(strProjectManifestPath, (const unsigned char *)strProjectManifestFormatted.c_str(), strProjectManifestFormatted.length()) ||
			!WriteDataToFile(strDeprecatedProjectManifestPath, (const unsigned char *)strProjectManifestFormatted.c_str(), strProjectManifestFormatted.length()) ||
			!WriteDataToFile(strVersionManifestPath, (const unsigned char *)strVersionManifestFormatted.c_str(), strVersionManifestFormatted.length()))
#else
		if (!WriteDataToFile(strProjectManifestPath, (const unsigned char *)strProjectManifestUnformatted.c_str(), strProjectManifestUnformatted.length()) ||
			!WriteDataToFile(strDeprecatedProjectManifestPath, (const unsigned char *)strProjectManifestUnformatted.c_str(), strProjectManifestUnformatted.length()) ||
			!WriteDataToFile(strVersionManifestPath, (const unsigned char *)strVersionManifestUnformatted.c_str(), strVersionManifestUnformatted.length()))
#endif
		{
			nRet = RETURN_VALUE::MANIFEST_WRITE_ERROR;
		}
	}

	cJSON_Delete(cJsonRoot);
	cJsonRoot = nullptr;

	switch (nRet)
	{
	case RETURN_VALUE::OK:
		printf("Manifest files generated.\r\n");
		break;
	case RETURN_VALUE::MANIFEST_WRITE_ERROR:
		printf("Cannot overwrite manifest file.\r\n");
		break;
	}

	RETURN(nRet);
}