#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>
#include <memory.h>
#include <sys/stat.h>
#include <winsock.h>
#pragma warning (push, 3)
#include <wintrust.h>
#pragma warning (pop)

#include <string.h>
#include <schannel.h>
#include "include/wincryptex.h"
#include "include/AvCSPActivator.h"
#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

#include "MyLog.h"



extern SecurityFunctionTable g_SecurityFunc;
extern BOOL LoadSecurityLibrary();
extern void UnloadSecurityLibrary();
extern void PrintHexDump(DWORD length, PBYTE buffer);
extern void DisplayWinVerifyTrustError (DWORD Status);

#ifndef SEC_I_CONTEXT_EXPIRED
	#define SEC_I_CONTEXT_EXPIRED            ((HRESULT)0x00090317L)
#endif /* SEC_I_CONTEXT_EXPIRED */

#define IO_BUFFER_SIZE  0x10000

#define MAX_PARAM_SIZE  512



using namespace std;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Пользовательские параметры по умолчанию , т.е. если не будут заданы в командной строке или в файле конфигурации
/////////////////////////////////

const LPSTR		config_file = "AvestTLS_GetFile.ini"; //  Поиск конфигурационного файла будет в текущем каталоге.

const LPSTR		log_file = "AvestTLS_GetFile.log";	//  Лог будет направлен в текущий каталог(может отличатся от того где запускаемый файл )
const INT		max_size = 2048;

const BOOL		useProxy = false;
const LPSTR		nameProxy = "proxy";
const INT		portProxy = 8080;

const LPSTR		nameServer = "ep.isc.by";
const INT		portServer = 443;

const LPSTR		subject = "user_ep@zavod_mail.by";	//certificate !!! индификатор пользователя обязательно свое - иначе ошибка поиска сертификата из хранилища и выход из программы
const LPSTR		pass=  "12345678";

const LPSTR		fromFile = "ep/downloadNSI?type=XML&table=STA";	// НСИ станции
const LPSTR		toFile = "DataFromEP.XML";					//  XML будет сохранен в  текущем каталоге

//////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Переменные для параметров.

// Файл конфигурации 
static LPSTR	chConfigFile = new char[MAX_PARAM_SIZE];

static LPSTR	chLogFile = new char[MAX_PARAM_SIZE]; 
static INT		iLogMaxSize = -1;


// Использовать прокси
static BOOL     fUseProxy;
// Если используем прокси
static LPSTR   pszProxyServer = new char[MAX_PARAM_SIZE];
static INT     iProxyPort      = -1;


// Сервер
static LPSTR    pszServerName = new char[MAX_PARAM_SIZE];
static INT      iPortNumber = -1;

// Строка для импорта данных
static LPSTR    pszFileName = new char[MAX_PARAM_SIZE];

// Файл для записи данных
static LPSTR	chSaveFile = new char[MAX_PARAM_SIZE];

// Сертификат
static LPSTR	pszUserName = new char[MAX_PARAM_SIZE];
static LPSTR	chUserPass = new char[MAX_PARAM_SIZE];

static int      fVerbose = 1;		// 1- краткая информация для отображения в консоле ,  2 - подробная

//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// объект Лога
MyLog* LogFile;
/// параметр сообщения для лога
char logText[MAX_PARAM_SIZE];


/// Установки лога
static void SetBeginLog(char * name_log, int max_size_log_kb)
{
	if (LogFile == NULL)
	{
		LogFile = new MyLog(string(name_log), max_size_log_kb);
		LogFile->BeginLog();
	}
}


/// вывод справки по командной строке и выход из программы
static void PrintHelp()
{
	//cout << "Параметры для командной строки:" << endl << endl;
	cout << "ВНИМАНИЕ!! Обозначение параметров  без знака '-', значение параметра сразу за ':'(без пробела )" << endl << endl;
	cout << "conf: - путь к файлу конфигурации, если не указать, файл по умолчанию будет искаться в текущем каталоге. " << endl;
	cout << "log:  - путь к файлу логирования, если не указать, файл по умолчанию будет записан в текущий каталог.\n\t Каталог для лога должен быть с правом записи. " << endl;
	cout << "user:  - одно из значений поля Субъект в составе сертификата - для однозначного выбора сертификата из личного хранилища. " << endl;
	cout << "pass:  - пин пароль к контейнеру сертификата, если указать неверно - будет выведено окно для ввода пароля. " << endl;
	cout << "from:  - путь с параметрами на сервере. " << endl;
	cout << "file:  - файл с расширением для сохранения данных с сервера. Файл будет перезаписан или создан.\n\t Если указан полный путь, то каталог должен быть с соответствующими правами на запись. " << endl;
	cout << "?, help, HELP -  данная справка." << endl << endl;
	cout << "Файл exe можно запускать без параметров или с любым количеством. Обязательно должен быть файл конфигурации с основными настройками.\n Параметры из командной строки более приоритетны, чем в файле конфигурации." << endl << endl;
	cout << "Пример: " << endl << endl;
	cout << "AvestTLS_GetFile.exe conf:\"c:\\Мои документы\\GetFile.ini\" log:\"D:\\DownLoad from EP\\mylog.log\" user:\"Иванов Петр Петрович\" pass:87654321 from:\"ep/downloadNSI?type=XML&table=STA\" file:\"D:\\DownLoad from EP\\FromEP.xml\" " << endl << endl;

	system("pause");
	exit(0);
}


/// поверка на наличия полного пути в имени файла, если нет - дополняем.
/// не проверяется наличие самого файла
static void FullPath(LPSTR *file_name)
{
	LPSTR buffer = *file_name; 

	for (int i = 0; i < (strlen(buffer)-1); i++)
	{
		/// проверка на сеть \\server1\ddd\file.log или полный локальный полный путь d:\ddd\primer.ini
		if ((buffer[i] == '\\' && buffer[i + 1] == '\\') || buffer[i] == ':')
			return;
	}
	
	TCHAR buffer_path[MAX_PARAM_SIZE];

	GetCurrentDirectory(MAX_PARAM_SIZE, buffer_path );
	if (buffer[0] != '\\')
		strcat(buffer_path, "\\");
	strcat(buffer_path, buffer);
	
	strcpy(*file_name, buffer_path);
}



/// функции чтения строки из файла конфигурации
static bool ReadStrFromConfig(LPSTR lpAppName, LPSTR lpKeyName, LPSTR fullPathConfigFile, LPSTR *val, LPSTR nameVal)
{
	LPSTR out = new char[MAX_PARAM_SIZE];
	GetPrivateProfileString(lpAppName, lpKeyName, "", out, MAX_PARAM_SIZE, fullPathConfigFile);
	if (strlen(out) == 0)
	{
		printf("-> !!! ОШИБКА - не найден параметр %s в разделе %s\n", lpKeyName, lpAppName);
		return false;
	}
	
	strcpy(*val, out);
	//cout << "\t" << nameVal << " =" << *val << endl;
	return true;
}
static bool ReadIntFromConfig(LPSTR lpAppName, LPSTR lpKeyName, LPSTR fullPathConfigFile, INT *val, LPSTR nameVal)
{
	UINT iout;
	iout=GetPrivateProfileInt(lpAppName, lpKeyName, -1, fullPathConfigFile);
	if (iout == MAXUINT) 
	{
		printf("-> !!! ОШИБКА - не найден параметр %s в разделе %s\n", lpKeyName, lpAppName);
		return false;
	}

	*val=iout;
	//cout << "\t" << nameVal << " =" << *val << endl;
	return true;
}



/// функция чтения из файла конфигурации для параметров, которые не были переданы в строке запуска exe.
/// если нет переменных в файле конфигурации - переменным присваеваем значения по умолчанию
static bool ReadFromConfig(LPSTR fullPathConfigFile)
{
	bool bRet = false;

	if (GetFileAttributes(fullPathConfigFile)== MAXUINT)
	{
		cout << "!!! ОШИБКА !!! Не найден файл конфигурации " << fullPathConfigFile << endl ;
		system("pause");
		goto ex;
	}

	cout << "\nПрисваивание значений из файла конфигурации " << fullPathConfigFile << endl ;

	// log
	if (strlen(chLogFile) == 0 && !ReadStrFromConfig("log", "log_file", fullPathConfigFile, &chLogFile, "chLogFile"))
		strcpy(chLogFile, log_file);
	if (iLogMaxSize==-1 && !ReadIntFromConfig("log", "max_size", fullPathConfigFile, &iLogMaxSize, "iLogMaxSize"))
		iLogMaxSize = max_size;

	// proxy
	if (!ReadIntFromConfig("proxy", "useProxy", fullPathConfigFile, &fUseProxy, "fUseProxy"))
		fUseProxy = useProxy;
	if(strlen(pszProxyServer) == 0 && !ReadStrFromConfig("proxy", "nameProxy", fullPathConfigFile, &pszProxyServer, "pszProxyServer"))
		strcpy(pszProxyServer, nameProxy);
	if (!ReadIntFromConfig("proxy", "portProxy", fullPathConfigFile, &iProxyPort, "iProxyPort"))
		iProxyPort=portProxy;

	//server
	if (strlen(pszServerName) == 0 && !ReadStrFromConfig("server", "nameServer", fullPathConfigFile, &pszServerName, "pszServerName"))
		strcpy(pszServerName, nameServer);
	if (iPortNumber==-1 && !ReadIntFromConfig("server", "portServer", fullPathConfigFile, &iPortNumber, "iPortNumber" ))
		iPortNumber=portServer;

	//certificate	!!! имя пользователя обязательно свое - иначе ошибка поиска сертификата из хранилища и выход из программы
	if (strlen(pszUserName) == 0 && !ReadStrFromConfig("certificate", "subject", fullPathConfigFile, &pszUserName, "pszUserName"))
		strcpy(pszUserName, subject);
	if (strlen(chUserPass) == 0 && !ReadStrFromConfig("certificate", "pass", fullPathConfigFile, &chUserPass, "chUserPass"))
		strcpy(chUserPass, pass);
	
	//params
	if (strlen(pszFileName) == 0 && !ReadStrFromConfig("params", "fromFile", fullPathConfigFile, &pszFileName, "pszFileName"))
		strcpy(pszFileName, fromFile);
	if (strlen(chSaveFile) == 0 && !ReadStrFromConfig("params", "toFile", fullPathConfigFile, &chSaveFile, "chSaveFile"))
		strcpy(chSaveFile, toFile);

	bRet = true;
	
	ex:
	cout << "--------------------------------------------- " << endl << endl;

	//system("pause");
	return bRet;



}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


static INT	noCache = 0;

static
SECURITY_STATUS
CreateCredentials(
    LPSTR pszUserName,
    PCredHandle phCreds);

static INT
ConnectToServer(
    LPSTR pszServerName,
    INT   iPortNumber,
    SOCKET *pSocket);

static
SECURITY_STATUS
PerformClientHandshake(
    SOCKET          Socket,
    PCredHandle     phCreds,
    LPSTR           pszServerName,
    CtxtHandle *    phContext,
    SecBuffer *     pExtraData);

static
SECURITY_STATUS
ClientHandshakeLoop(
    SOCKET          Socket,
    PCredHandle     phCreds,
    CtxtHandle *    phContext,
    BOOL            fDoInitialRead,
    SecBuffer *     pExtraData);

static
SECURITY_STATUS
HttpsGetFile(
    SOCKET          Socket,
    PCredHandle     phCreds,
    CtxtHandle *    phContext,
    LPSTR           pszFileName);

static 
void
DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal);

static 
DWORD
VerifyServerCertificate(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags);


static
LONG
DisconnectFromServer(
    SOCKET          Socket, 
    PCredHandle     phCreds,
    CtxtHandle *    phContext);

static void
DisplayConnectionInfo(
    CtxtHandle *phContext);

static void
GetNewClientCredentials(
    CredHandle *phCreds,
    CtxtHandle *phContext);

double 
DiffTime (SYSTEMTIME * start, SYSTEMTIME * end)
{
    double ret;
    if (start->wDayOfWeek > end->wDayOfWeek) end->wDayOfWeek+=7;
    ret=(end->wDayOfWeek-start->wDayOfWeek)*24;
    
    ret=(ret+end->wHour-start->wHour)*60;
    ret=(ret+end->wMinute-start->wMinute)*60;
    ret=(ret+end->wSecond-start->wSecond);
    ret+=(end->wMilliseconds-start->wMilliseconds)/1000.0;
    return ret;
}


static DWORD    dwProtocol      = SP_PROT_TLS1;
static ALG_ID   aiKeyExch       = 0;
static DWORD	cbDataReceived = 0;

static HCERTSTORE      hMyCertStore = NULL;
static SCHANNEL_CRED   SchannelCred;


int main(int argc, _TCHAR* argv[])
{


	WSADATA WsaData;
    SOCKET  Socket;

    int nConn = 1;		// кол-во попыток соеденения с сервером

    CredHandle hClientCreds;
    CtxtHandle hContext;
    SecBuffer  ExtraData;
    SECURITY_STATUS Status;

    PCCERT_CONTEXT pRemoteCertContext = NULL;
    PCCERT_CONTEXT pCurrRemoteCertContext = NULL;

    SYSTEMTIME start,end,end1;

	
	setlocale(LC_ALL, "Russian_Russia.1251"); //для платформы win разрешение вывода русского языка в консоль

	/// инициализация переменых параметров
	chConfigFile[0] = 0;
	chLogFile[0] = 0;
	pszProxyServer[0] = 0;
	pszFileName[0] = 0;
	chSaveFile[0] = 0;
	pszUserName[0] = 0;
	chUserPass[0] = 0;
	pszServerName[0] = 0;

	//////////////////////////////////////////////////////////////////////////////////////
	/// разбор командной строки
	if (argc>1) printf("Параметры командной строки:\n");
	string arg;
	for (int i = 1; i < argc; i++) 
	{
		arg = argv[i];
		if (arg == "?" || arg == "HELP" || arg == "help") PrintHelp();

		if (arg.substr(0, 5) == "conf:" &&  arg.length()>5)
			strcpy(chConfigFile, arg.substr(5).c_str());
		if (arg.substr(0, 4) == "log:" && arg.length()>4)
			strcpy(chLogFile, arg.substr(4).c_str());
		if (arg.substr(0, 5) == "user:" && arg.length()>5)
			strcpy(pszUserName, arg.substr(5).c_str());
		if (arg.substr(0, 5) == "pass:" && arg.length()>5)
			strcpy(chUserPass, arg.substr(5).c_str());
		if (arg.substr(0, 5) == "from:" && arg.length()>5)
			strcpy(pszFileName, arg.substr(5).c_str());
		if (arg.substr(0, 5) == "file:" && arg.length()>5)
			strcpy(chSaveFile, arg.substr(5).c_str());
		
			printf("\t argv[%i]=%s\n",i, argv[i]);
			//printf(argv[i]);printf("\n\n");
	}
	if (argc>1) printf("\n  Значение переменых из  командной строки:\n");
	if (strlen(chConfigFile) > 0)  cout << "\tchConfigFile = " << chConfigFile << endl;
	if (strlen(chLogFile) > 0) cout << "\tchLogFile = " << chLogFile << endl;
	if (strlen(pszUserName) > 0) cout << "\tpszUserName = " << pszUserName << endl;
	if (strlen(chUserPass) > 0) cout << "\tchUserPass = " << chUserPass << endl;
	if (strlen(pszFileName) > 0) cout << "\tpszFileName = " << pszFileName << endl;
	if (strlen(chSaveFile) > 0) cout << "\tchSaveFile = " << chSaveFile << endl;

	//////////////////////////////////////////////////////////////////////////////////////


	//////////////////////////////////////////////////////////////////////////////////////
	if (strlen(chConfigFile)==0)	// если файл конфигурации не передан в параметре строки, то берем по умолчанию 
		strcpy(chConfigFile, config_file);


	// Установки из файла конфигурации для параметров, которые не переданы в строке

	FullPath(&chConfigFile);
	if (!ReadFromConfig(chConfigFile))
		return(EXIT_FAILURE);
	
	FullPath(&chLogFile);
	FullPath(&chSaveFile);
	SetBeginLog(chLogFile, iLogMaxSize);

	// Выводим переменные с пользовательскими установками
	LogFile->WriteLine("   переменные с пользовательскими установками:");
	LogFile->WriteLine("\t chConfigFile= " + string(chConfigFile));
	LogFile->WriteLine("\t chLogFile= " + string(chLogFile));
	LogFile->WriteLine("\t iLogMaxSize= " + to_string(iLogMaxSize));
	LogFile->WriteLine("\t fUseProxy= " + to_string(fUseProxy));
	LogFile->WriteLine("\t pszProxyServer= " + string(pszProxyServer));
	LogFile->WriteLine("\t iProxyPort= " + to_string(iProxyPort));
	LogFile->WriteLine("\t pszServerName= " + string(pszServerName));
	LogFile->WriteLine("\t iPortNumber= " + to_string(iPortNumber));
	LogFile->WriteLine("\t pszFileName= " + string(pszFileName));
	LogFile->WriteLine("\t chSaveFile= " + string(chSaveFile));
	LogFile->WriteLine("\t pszUserName= " + string(pszUserName));
	LogFile->WriteLine("\t chUserPass= " + string(chUserPass));
	LogFile->WriteLine("\t ------------------------------------ ");

	
	//system("pause");


	//* # 1
	//* загрузка библиотек   
	if(!LoadSecurityLibrary())	
    {
        //printf("Error initializing the security library\n");
		LogFile->WriteLine("-->	Error initializing the security library\n");
        return 0;
    }

    //
    // Initialize the WinSock subsystem. # 2
    //
	/*
		Windows Sockets API (WSA), название которого было укорочено до Winsock. 
		Это техническая спецификация, которая определяет, как сетевое программное 
		обеспечение Windows будет получать доступ к сетевым сервисам, в том числе, TCP/IP. 
		Он определяет стандартный интерфейс между клиентским приложением 
		(таким как FTP клиент или веб-браузер) и внешним стеком протоколов TCP/IP. 
		Он основывается на API модели сокетов Беркли, использующейся в BSD для установки 
		соединения между программами.
	*/

    int iRet = WSAStartup(0x0101, &WsaData);    

    if (iRet == SOCKET_ERROR)
    {
        //printf("Error %d returned by WSAStartup\n", GetLastError());
		LogFile->WriteLine("-->\t Error" + to_string(GetLastError()) + " returned by WSAStartup\n");
        return 0;
    }

    //
    // Create credentials.
    //

	try
	{
		if (CreateCredentials(pszUserName, &hClientCreds) )
		{
			//printf("Error creating credentials\n");
			LogFile->WriteLine("-->\t Ошибка выбора сертификата, права не подтверждены. \n");
			return 0;
		}
	}
	catch (exception ex )
	{
		string  exs = ex.what();
		LogFile->WriteLine("-->\t Ошибка выбора сертификата, права не подтверждены. \n "+ exs);
		return 0;
	}


    GetSystemTime(&start);

    {
	    int iConn;

		for (iConn = 0; iConn < nConn; iConn++)
		{
			//
			// Connect to server.
			//

			if(ConnectToServer(pszServerName, iPortNumber, &Socket))
			{
				//printf("Error connecting to server\n");
				LogFile->WriteLine("-->\t Error connecting to server\n");
				return 0;
			}


			//
			// Perform handshake
			//
		//////////////////////////////////////////////////////////////////////// 
		/////////////  в т.ч.  ВЫзов окна сертификата
		//////////////////////////////////////////////////////////////////////
			if(PerformClientHandshake(Socket,
									  &hClientCreds,
									  pszServerName,
									  &hContext,
									  &ExtraData))
			{
				//printf("Error performing handshake\n");
				LogFile->WriteLine("-->\t Error performing handshake\n");
				
				return 0;
			}

		////////////////////////////////////////////////////////////////
			//
			// Authenticate server's credentials.
			//


			// Get server's certificate.
			Status = g_SecurityFunc.QueryContextAttributes(&hContext,
											SECPKG_ATTR_REMOTE_CERT_CONTEXT,
											(PVOID)&pRemoteCertContext);
			if(Status != SEC_E_OK)
			{
				//printf("Error 0x%x querying remote certificate\n", Status);
				LogFile->WriteLine("-->\t Error "+to_string(Status )+" querying remote certificate\n");
				return 0;
			}

			if (!pCurrRemoteCertContext
			  || pCurrRemoteCertContext->cbCertEncoded != pRemoteCertContext->cbCertEncoded
			  || memcmp (pCurrRemoteCertContext->pbCertEncoded, pRemoteCertContext->pbCertEncoded, pCurrRemoteCertContext->cbCertEncoded)
			  || 1
			  )
			{
			// Display server certificate chain.
			if (fVerbose >= 1)
				DisplayCertChain(pRemoteCertContext, FALSE);

			// Attempt to validate server certificate.
			Status = VerifyServerCertificate(pRemoteCertContext,
							 pszServerName,
							 0);
				if(Status)
				{
					//printf("**** Error authenticating server credentials!\n");
					LogFile->WriteLine("-->\t **** Error authenticating server credentials!\n");
					//
					// At this point, the client could decide to not continue
					//
				}
			}

			if (pCurrRemoteCertContext)
				CertFreeCertificateContext (pCurrRemoteCertContext);
			pCurrRemoteCertContext = pRemoteCertContext;

			//
			// Display connection info. 
			//

			if (fVerbose >= 1)
				DisplayConnectionInfo(&hContext);


			//
			// Read file from server.
			//

			if(HttpsGetFile(Socket, 
							&hClientCreds,
							&hContext, 
							pszFileName))
			{
				//printf("Error fetching file from server\n");
				LogFile->WriteLine("-->\t Error fetching file from server\n");
				return 0;
			}

			//
			// Cleanup.
			//

			if(DisconnectFromServer(Socket, &hClientCreds, &hContext))
			{
				//printf("Error disconnecting from server\n");
				LogFile->WriteLine("-->\t Error disconnecting from server\n");
			}

			// Close socket.
			closesocket(Socket);

			if (!iConn) GetSystemTime(&end1);
		

		}	// END for (iConn = 0; iConn < nConn; iConn++)
	}

    GetSystemTime(&end);

    // Free SSPI credentials handle.
    g_SecurityFunc.FreeCredentialsHandle(&hClientCreds);

    // Shutdown WinSock subsystem.
    WSACleanup();

    // Close "MY" certificate store.
    if(hMyCertStore)
    {
        CertCloseStore(hMyCertStore, 0);
    }

    //printf("%d connections, %d bytes in %.3f seconds;\n", nConn, cbDataReceived, DiffTime (&start, &end));
	LogFile->WriteLine("\t "+ to_string(nConn) +" connections, "+ to_string(cbDataReceived) +" bytes in "+ to_string(DiffTime(&start, &end)) +" seconds; ");

    if (nConn > 1)
    {
		//printf("First connection: %.3f seconds;\n", DiffTime (&start, &end1));
		LogFile->WriteLine("\t First connection: " + to_string(DiffTime(&start, &end1))+ " seconds; ");
		//printf("Other connections: %.3f seconds;\n", DiffTime (&end1, &end)/(nConn-1));
		LogFile->WriteLine("\t Other connections: " + to_string(DiffTime(&end1, &end) / (nConn - 1)) + " seconds; ");

    }

	LogFile->EndLog();

	//system("pause");
	return 0;
}


/*****************************************************************************/
/////////////// ВЫБОР СЕРТИФИКАТА ИЗ ХРАНИЛИЩА 

static
SECURITY_STATUS
CreateCredentials(
    LPSTR pszUserName,              // in
    PCredHandle phCreds)            // out
{
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;

    DWORD           cSupportedAlgs = 0;
    ALG_ID          rgbSupportedAlgs[16];

    PCCERT_CONTEXT  pCertContext = NULL;

    // Open the "MY" certificate store, which is where Internet Explorer
    // stores its client certificates.
    if(hMyCertStore == NULL)
    {
        hMyCertStore = CertOpenSystemStore(0, "MY");

        if(!hMyCertStore)
        {
            //printf("**** Error 0x%x returned by CertOpenSystemStore\n",GetLastError());

			snprintf(logText, sizeof(logText), "**** Error 0x%x returned by CertOpenSystemStore\n нет доступа к хранилющу сертификатов на локальном комп. у пользователя", GetLastError());

			LogFile->WriteLine(logText);

            return SEC_E_NO_CREDENTIALS;
        }
    }

    //
    // If a user name is specified, then attempt to find a client
    // certificate. Otherwise, just create a NULL credential.
    //

    if(pszUserName)
    {
        // Find client certificate. Note that this sample just searchs for a 
        // certificate that contains the user name somewhere in the subject name.
        // A real application should be a bit less casual.
        pCertContext = CertFindCertificateInStore(hMyCertStore, 
                                                  X509_ASN_ENCODING, 
                                                  0,
                                                  CERT_FIND_SUBJECT_STR_A,
                                                  pszUserName,
                                                  NULL);
        if(pCertContext == NULL)
        {
            //printf("**** Error 0x%x returned by CertFindCertificateInStore\n", GetLastError());
			snprintf(logText, sizeof(logText), "**** Error 0x%x returned by CertFindCertificateInStore\n не найден сертификат по индификатору :%s из subject name в хранилище.", GetLastError(), pszUserName);
			LogFile->WriteLine(logText);
            return SEC_E_NO_CREDENTIALS;
        }
    }
	
	//////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////
	////////////////////////////

	DWORD iKeySpec;
	HCRYPTPROV hProv;
	
	if(!CryptAcquireCertificatePrivateKey(
		pCertContext,
		CRYPT_SILENT,
		0,
		&hProv,
		&iKeySpec,
		NULL))
	{
		//printf("\n\nError open cryptoprovider\n\n");
		snprintf(logText, sizeof(logText), "**** Error open cryptoprovider\n нет доступа к контейнеру ключей криптопровайдера Avest\n или сбой в инициализации контейнера.");
		LogFile->WriteLine(logText);
	}

	 // Установка параметров в соответствии с паролем.
    if(CryptSetProvParam(
        hProv,
        PP_KEYEXCHANGE_PIN,
        (BYTE*)chUserPass,
        0))
    {
		//printf("\n\nCryptSetProvParam succeeded.\n\n");
		snprintf(logText, sizeof(logText), "\t пин код контейнера установлен.");
		LogFile->WriteLine(logText);

    }
    else
    {
        //printf("\n\nError during CryptSetProvParam.\n\n");
		snprintf(logText, sizeof(logText), "**** Error неверный пароль %s или ошибка доступа к контейнеру ключей.", chUserPass);
		LogFile->WriteLine(logText);
    }
	///////////////////////////////
	/////////////////////////////////////////////
	/////////////////////////////////////////////////////////////



    //
    // Build Schannel credential structure. Currently, this sample only
    // specifies the protocol to be used (and optionally the certificate, 
    // of course). Real applications may wish to specify other parameters 
    // as well.
    //

    ZeroMemory(&SchannelCred, sizeof(SchannelCred));

    SchannelCred.dwVersion  = SCHANNEL_CRED_VERSION;
    if(pCertContext)
    {
        SchannelCred.cCreds     = 1;
        SchannelCred.paCred     = &pCertContext;
    }

    SchannelCred.grbitEnabledProtocols = dwProtocol;

    if(aiKeyExch)
    {
        rgbSupportedAlgs[cSupportedAlgs++] = aiKeyExch;
    }

    if(cSupportedAlgs)
    {
        SchannelCred.cSupportedAlgs    = cSupportedAlgs;
        SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
    }

    SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;

	///// IZM 24_08_2017 
	//	SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
	///// END IZM 24_08_2017 

    //
    // Create an SSPI credential.
    //

    Status = g_SecurityFunc.AcquireCredentialsHandleA(
                        NULL,                   // Name of principal    
                        UNISP_NAME_A,           // Name of package
                        SECPKG_CRED_OUTBOUND,   // Flags indicating use
                        NULL,                   // Pointer to logon ID
                        &SchannelCred,          // Package specific data
                        NULL,                   // Pointer to GetKey() func
                        NULL,                   // Value to pass to GetKey()
                        phCreds,                // (out) Cred Handle
                        &tsExpiry);             // (out) Lifetime (optional)
  
	
	
	if(Status != SEC_E_OK)
    {
        //printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);
		snprintf(logText, sizeof(logText), "**** Error 0x%x returned by AcquireCredentialsHandle\n не удалось создать на основе выбранного сертификата удостоверение безопасности клиента для протокола TLS.", Status);
		LogFile->WriteLine(logText);

        return Status;
    }


    //
    // Free the certificate context. Schannel has already made its own copy.
    //

    if(pCertContext)
    {
        //CertFreeCertificateContext(pCertContext);
    }


    return SEC_E_OK;
}






/*****************************************************************************/
static INT
ConnectToServer(
    LPSTR    pszServerName, // in
    INT      iPortNumber,   // in
    SOCKET * pSocket)       // out
{
    SOCKET Socket;
    struct sockaddr_in sin;
    struct hostent *hp;

    Socket = socket(PF_INET, SOCK_STREAM, 0);
    if(Socket == INVALID_SOCKET)
    {
        //printf("**** Error %d creating socket\n", WSAGetLastError());

		snprintf(logText, sizeof(logText), "****  Error %d creating socket", WSAGetLastError());
		LogFile->WriteLine(logText);
		return WSAGetLastError();
    }

    if(fUseProxy)
    {
        sin.sin_family = AF_INET;
        sin.sin_port = ntohs((u_short)iProxyPort);

        if((hp = gethostbyname(pszProxyServer)) == NULL)
        {
            //printf("**** Error %d returned by gethostbyname\n", WSAGetLastError());
			snprintf(logText, sizeof(logText), "****  Error %d returned by gethostbyname\n возможно неправильные настройки прокси.", WSAGetLastError());
			LogFile->WriteLine(logText);

            return WSAGetLastError();
        }
        else
        {
            memcpy(&sin.sin_addr, hp->h_addr, 4);
        }
    }
    else
    {
        sin.sin_family = AF_INET;
        sin.sin_port = htons((u_short)iPortNumber);

        if((hp = gethostbyname(pszServerName)) == NULL)
        {
            //printf("**** Error %d returned by gethostbyname\n", WSAGetLastError());
			snprintf(logText, sizeof(logText), "****  Error %d returned by gethostbyname\n возможно неправильные настройка сервера.", WSAGetLastError());
			LogFile->WriteLine(logText);
            return WSAGetLastError();
        }
        else
        {
            memcpy(&sin.sin_addr, hp->h_addr, 4);
        }
    }

    if(connect(Socket, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR)
    {
        //printf("**** Error %d connecting to \"%s\" (%s)\n", 
        //    WSAGetLastError(),
        //    pszServerName, 
        //    inet_ntoa(sin.sin_addr));

		snprintf(logText, sizeof(logText), "**** Error %d connecting to \"%s\" (%s)",
			WSAGetLastError(),
			pszServerName,
			inet_ntoa(sin.sin_addr));
		LogFile->WriteLine(logText);
		
		closesocket(Socket);
        return WSAGetLastError();
    }


	
	if(fUseProxy)
    {
        BYTE  pbMessage[200]; 
        DWORD cbMessage;

        // Build message for proxy server
        strcpy((char *)pbMessage, "CONNECT ");
        strcat((char *)pbMessage, pszServerName);
        strcat((char *)pbMessage, ":");
        _itoa(iPortNumber, (char *)(pbMessage + strlen((char *)pbMessage)), 10);
        strcat((char *)pbMessage, " HTTP/1.0\r\nUser-Agent: webclient\r\n\r\n");
        cbMessage = (DWORD)strlen((char *)pbMessage);

        // Send message to proxy server
        if(send(Socket, (char *)pbMessage, cbMessage, 0) == SOCKET_ERROR)
        {
            //printf("**** Error %d sending message to proxy!\n", WSAGetLastError());
			snprintf(logText, sizeof(logText), "**** Error %d sending message to proxy!", WSAGetLastError());
			LogFile->WriteLine(logText);
			return WSAGetLastError();
        }

        // Receive message from proxy server
        cbMessage = recv(Socket, (char *)pbMessage, 200, 0);
        if(cbMessage == SOCKET_ERROR)
        {
            //printf("**** Error %d receiving message from proxy", WSAGetLastError());
			snprintf(logText, sizeof(logText), "**** Error %d receiving message from proxy!", WSAGetLastError());
			LogFile->WriteLine(logText);

            return WSAGetLastError();
        }

        // this sample is limited but in normal use it 
        // should continue to receive until CR LF CR LF is received
    }

    *pSocket = Socket;

    return SEC_E_OK;
}





/*****************************************************************************/
static
LONG
DisconnectFromServer(
    SOCKET          Socket, 
    PCredHandle     phCreds,
    CtxtHandle *    phContext)
{
    DWORD           dwType;
    PBYTE           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;

    //
    // Notify schannel that we are about to close the connection.
    //

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = g_SecurityFunc.ApplyControlToken(phContext, &OutBuffer);

    if(FAILED(Status)) 
    {
        //printf("**** Error 0x%x returned by ApplyControlToken\n", Status);
		snprintf(logText, sizeof(logText), "**** Error 0x%x returned by ApplyControlToken\n", Status);
		LogFile->WriteLine(logText);
        goto cleanup;
    }

    //
    // Build an SSL close notify message.
    //

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = g_SecurityFunc.InitializeSecurityContextA(
                    phCreds,
                    phContext,
                    NULL,
                    dwSSPIFlags,
                    0,
                    SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

    if(FAILED(Status)) 
    {
        //printf("**** Error 0x%x returned by InitializeSecurityContext\n", Status);
		snprintf(logText, sizeof(logText), "**** Error 0x % x returned by InitializeSecurityContext", Status);
		LogFile->WriteLine(logText);
        goto cleanup;
    }

    pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
    cbMessage = OutBuffers[0].cbBuffer;


    //
    // Send the close notify message to the server.
    //

    if(pbMessage != NULL && cbMessage != 0)
    {
        cbData = send(Socket, (char *)pbMessage, cbMessage, 0);
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
            Status = WSAGetLastError();
            //printf("**** Error %d sending close notify\n", Status);
			snprintf(logText, sizeof(logText), "**** Error %d sending close notify", Status);
			LogFile->WriteLine(logText);
            goto cleanup;
        }

    if (fVerbose >= 1)
    {
        printf("Sending Close Notify\n");
        printf("%d bytes of handshake data sent\n", cbData);
    }

        if (fVerbose >= 2)
        {
            PrintHexDump(cbData, pbMessage);
            printf("\n");
        }

        // Free output buffer.
        g_SecurityFunc.FreeContextBuffer(pbMessage);
    }
    

cleanup:

    // Free the security context.
    g_SecurityFunc.DeleteSecurityContext(phContext);

    // Close the socket.
    closesocket(Socket);

    return Status;
}




/*****************************************************************************/
static
SECURITY_STATUS
PerformClientHandshake(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    LPSTR           pszServerName,  // in
    CtxtHandle *    phContext,      // out
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

// dwSSPIFlags =Detect messages received out of sequence
				// Detect replayed messages that have been encoded by using the EncryptMessage or MakeSignature functions.
				// Encrypt messages by using the EncryptMessage function
				// ??? 
				// The security package allocates output buffers for you. When you have finished using the output buffers, free them by calling the FreeContextBuffer function.
				// Support a stream-oriented connection



    //
    //  Initiate a ClientHello message and generate a token.
    //

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;


    scRet = g_SecurityFunc.InitializeSecurityContextA(
                    phCreds,
                    NULL,
                    noCache ? NULL : pszServerName,
                    dwSSPIFlags,
                    0,
                    SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

	

    if(scRet != SEC_I_CONTINUE_NEEDED)
    {
        //printf("**** Error %d returned by InitializeSecurityContext (1)\n", scRet);
		snprintf(logText, sizeof(logText), "**** Error %d returned by InitializeSecurityContext (1)\n не удалось установить защищенное соединение с сервером %s", scRet, pszServerName);
		LogFile->WriteLine(logText); 

        return scRet;
    }

    // Send response to server if there is one.
    
	
	if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
        cbData = send(Socket,
                      (const char*)OutBuffers[0].pvBuffer,
                      OutBuffers[0].cbBuffer,
                      0);
    

		if(cbData == SOCKET_ERROR || cbData == 0)
        {
            //printf("**** Error %d sending data to server (1)\n", WSAGetLastError());
			snprintf(logText, sizeof(logText), "**** Error %d sending data to server (1)", WSAGetLastError());
			LogFile->WriteLine(logText);

            g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
            g_SecurityFunc.DeleteSecurityContext(phContext);
            return SEC_E_INTERNAL_ERROR;
        }

		if (fVerbose >= 1)
		{
			printf("%d bytes of handshake data sent\n", cbData);
		}


        if (fVerbose >= 2)
        {
            PrintHexDump(cbData,(PBYTE)OutBuffers[0].pvBuffer);
            printf("\n");
        }

        // Free output buffer.
        g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }


    return ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData);
}






/*****************************************************************************/
static
SECURITY_STATUS
ClientHandshakeLoop(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle *    phContext,      // in, out
    BOOL            fDoInitialRead, // in
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   InBuffer;
    SecBuffer       InBuffers[2];
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    PUCHAR          IoBuffer;
    DWORD           cbIoBuffer;
    BOOL            fDoRead;


    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    //
    // Allocate data buffer.
    //

    IoBuffer = (PUCHAR)LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
    if(IoBuffer == NULL)
    {
        //printf("**** Out of memory (1)\n");
		snprintf(logText, sizeof(logText), "**** Out of memory (1)");
		LogFile->WriteLine(logText);
		return SEC_E_INTERNAL_ERROR;
    }
    cbIoBuffer = 0;

    fDoRead = fDoInitialRead;


    // 
    // Loop until the handshake is finished or an error occurs.
    //

    scRet = SEC_I_CONTINUE_NEEDED;

    while(scRet == SEC_I_CONTINUE_NEEDED        ||
          scRet == SEC_E_INCOMPLETE_MESSAGE     ||
          scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
   {

        //
        // Read data from server.
        //

        if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if(fDoRead)
            {
                cbData = recv(Socket, 
                              (char *)(IoBuffer + cbIoBuffer), 
                              IO_BUFFER_SIZE - cbIoBuffer, 
                              0);
                if(cbData == SOCKET_ERROR)
                {
                    //printf("**** Error %d reading data from server\n", WSAGetLastError());
					snprintf(logText, sizeof(logText), "**** Error %d reading data from server", WSAGetLastError());
					LogFile->WriteLine(logText);

                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else if(cbData == 0)
                {
                    //printf("**** Server unexpectedly disconnected\n");
					snprintf(logText, sizeof(logText), "**** Server unexpectedly disconnected");
					LogFile->WriteLine(logText);
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

		        if (fVerbose >= 1)
                    printf("%d bytes of handshake data received\n", cbData);

	            if (fVerbose >= 2)
                {
                    PrintHexDump(cbData, IoBuffer + cbIoBuffer);
                    printf("\n");
                }

                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }


        //
        // Set up the input buffers. Buffer 0 is used to pass in data
        // received from the server. Schannel will consume some or all
        // of this. Leftover data (if any) will be placed in buffer 1 and
        // given a buffer type of SECBUFFER_EXTRA.
        //

        InBuffers[0].pvBuffer   = IoBuffer;
        InBuffers[0].cbBuffer   = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers       = 2;
        InBuffer.pBuffers       = InBuffers;
        InBuffer.ulVersion      = SECBUFFER_VERSION;

        //
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        //

        OutBuffers[0].pvBuffer  = NULL;
        OutBuffers[0].BufferType= SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer  = 0;

        OutBuffer.cBuffers      = 1;
        OutBuffer.pBuffers      = OutBuffers;
        OutBuffer.ulVersion     = SECBUFFER_VERSION;

        //
        // Call InitializeSecurityContext.
        //

        scRet = g_SecurityFunc.InitializeSecurityContextA(phCreds,
                                          phContext,
                                          NULL,
                                          dwSSPIFlags,
                                          0,
                                          SECURITY_NATIVE_DREP,
                                          &InBuffer,
                                          0,
                                          NULL,
                                          &OutBuffer,
                                          &dwSSPIOutFlags,
                                          &tsExpiry);

        //
        // If InitializeSecurityContext was successful (or if the error was 
        // one of the special extended ones), send the contends of the output
        // buffer to the server.
        //

        if(scRet == SEC_E_OK                ||
           scRet == SEC_I_CONTINUE_NEEDED   ||
           FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
        {
            if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
                cbData = send(Socket,
                              (const char*)OutBuffers[0].pvBuffer,
                              OutBuffers[0].cbBuffer,
                              0);
                if(cbData == SOCKET_ERROR || cbData == 0)
                {
                    //printf("**** Error %d sending data to server (2)\n",  WSAGetLastError());
					snprintf(logText, sizeof(logText), "**** Error %d sending data to server (2)", WSAGetLastError());
					LogFile->WriteLine(logText);
                    g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
                    g_SecurityFunc.DeleteSecurityContext(phContext);
                    return SEC_E_INTERNAL_ERROR;
                }

		if (fVerbose >= 1)
                    printf("%d bytes of handshake data sent\n", cbData);

	        if (fVerbose >= 2)
                {
                    PrintHexDump(cbData, (PBYTE)OutBuffers[0].pvBuffer);
                    printf("\n");
                }

                // Free output buffer.
                g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }


        //
        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        //

        if(scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }


        //
        // If InitializeSecurityContext returned SEC_E_OK, then the 
        // handshake completed successfully.
        //

        if(scRet == SEC_E_OK)
        {
            //
            // If the "extra" buffer contains data, this is encrypted application
            // protocol layer stuff. It needs to be saved. The application layer
            // will later decrypt it with DecryptMessage.
            //

			if (fVerbose >= 1)
			{
				printf("Handshake was successful\n");

			}

            if(InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED, 
                                                  InBuffers[1].cbBuffer);
                if(pExtraData->pvBuffer == NULL)
                {
                    //printf("**** Out of memory (2)\n");
					snprintf(logText, sizeof(logText), "**** Out of memory (2)");
					LogFile->WriteLine(logText);
                    return SEC_E_INTERNAL_ERROR;
                }

                MoveMemory(pExtraData->pvBuffer,
                           IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                           InBuffers[1].cbBuffer);

                pExtraData->cbBuffer   = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;

                printf("%d bytes of app data was bundled with handshake data\n",
                    pExtraData->cbBuffer);
            }
            else
            {
                pExtraData->pvBuffer   = NULL;
                pExtraData->cbBuffer   = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            //
            // Bail out to quit
            //

            break;
        }


        //
        // Check for fatal error.
        //

        if(FAILED(scRet))
        {
            //printf("**** Error 0x%x returned by InitializeSecurityContext (2)\n", scRet);
			snprintf(logText, sizeof(logText), "**** Error 0x % x returned by InitializeSecurityContext(2)", scRet);
			LogFile->WriteLine(logText);
            break;
        }


        //
        // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
        // then the server just requested client authentication. 
        //

        if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            //
            // Display trusted issuers info. 
            //

            GetNewClientCredentials(phCreds, phContext);


            //
            // Now would be a good time perhaps to prompt the user to select
            // a client certificate and obtain a new credential handle, 
            // but I don't have the energy nor inclination.
            //
            // As this is currently written, Schannel will send a "no 
            // certificate" alert to the server in place of a certificate. 
            // The server might be cool with this, or it might drop the 
            // connection.
            // 

            // Go around again.
            fDoRead = FALSE;
            scRet = SEC_I_CONTINUE_NEEDED;
            continue;
        }


        //
        // Copy any leftover data from the "extra" buffer, and go around
        // again.
        //

        if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(IoBuffer,
                       IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                       InBuffers[1].cbBuffer);

            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    // Delete the security context in the case of a fatal error.
    if(FAILED(scRet))
    {
        g_SecurityFunc.DeleteSecurityContext(phContext);
    }

    LocalFree(IoBuffer);

    return scRet;
}







/*****************************************************************************/
static
SECURITY_STATUS
HttpsGetFile(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle *    phContext,      // in
    LPSTR           pszFileName)    // in
{
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS scRet;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
    SecBuffer *     pDataBuffer;
    SecBuffer *     pExtraBuffer;
    SecBuffer       ExtraBuffer;

    PBYTE pbIoBuffer;
    DWORD cbIoBuffer;
    DWORD cbIoBufferLength;
    PBYTE pbMessage;
    DWORD cbMessage;

    DWORD cbData;
    INT   i;


    //
    // Read stream encryption properties.
    //

    scRet = g_SecurityFunc.QueryContextAttributes(phContext,
                                   SECPKG_ATTR_STREAM_SIZES,
                                   &Sizes);
    if(scRet != SEC_E_OK)
    {
        //printf("**** Error 0x%x reading SECPKG_ATTR_STREAM_SIZES\n", scRet);
		snprintf(logText, sizeof(logText), "**** Error 0x%x reading SECPKG_ATTR_STREAM_SIZES\n ошибка получения данных с установок сервера \n(размеры буферов для заголовка, блока данных и трейлера при шифровании) ", scRet);
		LogFile->WriteLine(logText);
        return scRet;
    }

    if (fVerbose >= 1)
    printf("\nHeader: %d, Trailer: %d, MaxMessage: %d\n",
        Sizes.cbHeader,
        Sizes.cbTrailer,
        Sizes.cbMaximumMessage);

    //
    // Allocate a working buffer. The plaintext sent to EncryptMessage
    // should never be more than 'Sizes.cbMaximumMessage', so a buffer 
    // size of this plus the header and trailer sizes should be safe enough.
    // 

    cbIoBufferLength = Sizes.cbHeader + 
                       Sizes.cbMaximumMessage +
                       Sizes.cbTrailer;

    pbIoBuffer = (PBYTE)LocalAlloc(LMEM_FIXED, cbIoBufferLength);
    if(pbIoBuffer == NULL)
    {
        //printf("**** Out of memory (2)\n");
		snprintf(logText, sizeof(logText), "**** Out of memory (2)");
		LogFile->WriteLine(logText);
        return SEC_E_INTERNAL_ERROR;
    }


    //
    // Build an HTTP request to send to the server.
    //

    // Remove the trailing backslash from the filename, should one exist.
    if(pszFileName && 
       strlen(pszFileName) > 1 && 
       pszFileName[strlen(pszFileName) - 1] == '/')
    {
        pszFileName[strlen(pszFileName)-1] = 0;
    }

    // Build the HTTP request offset into the data buffer by "header size"
    // bytes. This enables Schannel to perform the encryption in place,
    // which is a significant performance win.
    pbMessage = pbIoBuffer + Sizes.cbHeader;

    // Build HTTP request. Note that I'm assuming that this is less than
    // the maximum message size. If it weren't, it would have to be broken up.
    sprintf((char *)pbMessage, 
            "GET /%s HTTP/1.0\r\nUser-Agent: Webclient\r\nAccept:*/*\r\n\r\n", 
            pszFileName);

	if (fVerbose >= 1) 
		printf("\nHTTP request: %s\n", pbMessage);

    cbMessage = (DWORD)strlen((char *)pbMessage);

    if (fVerbose >= 1)
	printf("Sending plaintext: %d bytes\n", cbMessage);

    if (fVerbose >= 2)
    {
        PrintHexDump(cbMessage, pbMessage);
        printf("\n");
    }

    //
    // Encrypt the HTTP request.
    //

    Buffers[0].pvBuffer     = pbIoBuffer;
    Buffers[0].cbBuffer     = Sizes.cbHeader;
    Buffers[0].BufferType   = SECBUFFER_STREAM_HEADER;

    Buffers[1].pvBuffer     = pbMessage;
    Buffers[1].cbBuffer     = cbMessage;
    Buffers[1].BufferType   = SECBUFFER_DATA;

    Buffers[2].pvBuffer     = pbMessage + cbMessage;
    Buffers[2].cbBuffer     = Sizes.cbTrailer;
    Buffers[2].BufferType   = SECBUFFER_STREAM_TRAILER;

    Buffers[3].BufferType   = SECBUFFER_EMPTY;

    Message.ulVersion       = SECBUFFER_VERSION;
    Message.cBuffers        = 4;
    Message.pBuffers        = Buffers;

    scRet = g_SecurityFunc.EncryptMessage(phContext, 0, &Message, 0);

    if(FAILED(scRet))
    {
        //printf("**** Error 0x%x returned by EncryptMessage\n", scRet);
		snprintf(logText, sizeof(logText), "**** Error 0x%x returned by EncryptMessage\n", scRet);
		LogFile->WriteLine(logText);
        return scRet;
    }


    // 
    // Send the encrypted data to the server.
    //

    cbData = send(Socket,
                  (char *)pbIoBuffer,
                  Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
                  0);
    if(cbData == SOCKET_ERROR || cbData == 0)
    {
        //printf("**** Error %d sending data to server (3)\n",WSAGetLastError());
		snprintf(logText, sizeof(logText), "**** Error %d sending data to server (3)", WSAGetLastError());
		LogFile->WriteLine(logText);
        g_SecurityFunc.DeleteSecurityContext(phContext);
        return SEC_E_INTERNAL_ERROR;
    }

    if (fVerbose >= 1)
		printf("%d bytes of application data sent\n", cbData);

    if (fVerbose >= 2)
    {
        PrintHexDump(cbData, pbIoBuffer);
        printf("\n");
    }

    //
    // Read data from server until done. Декриптуем и результат записываем в файл.
    //
	
	BOOL Save_XML = TRUE; // указатель, если файл открылся на запись, то TRUE
	FILE *fp;

	try 
	{
		if((fp=fopen(chSaveFile, "wb+"))==NULL)
		{
			//printf("\n\nERROR OPEN FILE %20s.\n\n", chSaveFile);
			snprintf(logText, sizeof(logText), "**** ERROR OPEN FILE %20s.", chSaveFile);
			LogFile->WriteLine(logText);
			Save_XML=FALSE;
		}
	}
	catch (...)
	{
		snprintf(logText, sizeof(logText), "**** ERROR OPEN FILE %20s.", chSaveFile);
		LogFile->WriteLine(logText);
		Save_XML = FALSE;
	}


    cbIoBuffer = 0;
	int kol_while =0;
    while(TRUE)
    {
		kol_while += 1;
        //
        // Read some data.
        //

        if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            cbData = recv(Socket, 
                          (char *)(pbIoBuffer + cbIoBuffer), 
                          cbIoBufferLength - cbIoBuffer, 
                          0);
            if(cbData == SOCKET_ERROR)
            {
                //printf("**** Error %d reading data from server\n", WSAGetLastError());
				snprintf(logText, sizeof(logText), "**** Error %d reading data from server\n", WSAGetLastError());
				LogFile->WriteLine(logText);

                scRet = SEC_E_INTERNAL_ERROR;
                break;
            }
            else if(cbData == 0)
            {
                // Server disconnected.
                if(cbIoBuffer)
                {
                    //printf("**** Server unexpectedly disconnected\n");
					snprintf(logText, sizeof(logText), "**** Server unexpectedly disconnected");
					LogFile->WriteLine(logText);
                    scRet = SEC_E_INTERNAL_ERROR;
                    return scRet;
                }
                else
                {
                    break;
                }
            }
            else
            {
				if (fVerbose >= 1)
                    printf("%d bytes of (encrypted) application data received\n", cbData);

			    if (fVerbose >= 2)
				{
                    PrintHexDump(cbData, pbIoBuffer + cbIoBuffer);
                    printf("\n");
                }

                cbIoBuffer += cbData;
            }
        }

        // 
        // Attempt to decrypt the received data.
        //

        Buffers[0].pvBuffer     = pbIoBuffer;
        Buffers[0].cbBuffer     = cbIoBuffer;
        Buffers[0].BufferType   = SECBUFFER_DATA;

        Buffers[1].BufferType   = SECBUFFER_EMPTY;
        Buffers[2].BufferType   = SECBUFFER_EMPTY;
        Buffers[3].BufferType   = SECBUFFER_EMPTY;

        Message.ulVersion       = SECBUFFER_VERSION;
        Message.cBuffers        = 4;
        Message.pBuffers        = Buffers;

        scRet = g_SecurityFunc.DecryptMessage(phContext, &Message, 0, NULL);

        if(scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            // The input buffer contains only a fragment of an
            // encrypted record. Loop around and read some more
            // data.
            continue;
        }

        // Server signalled end of session
        if(scRet == SEC_I_CONTEXT_EXPIRED)
            break;

        if( scRet != SEC_E_OK && 
            scRet != SEC_I_RENEGOTIATE && 
            scRet != SEC_I_CONTEXT_EXPIRED)
        {
            //printf("**** Error 0x%x returned by DecryptMessage\n", scRet);
			snprintf(logText, sizeof(logText), "**** Error 0x%x returned by DecryptMessage\n", scRet);
			LogFile->WriteLine(logText);
            return scRet;
        }

        // Locate data and (optional) extra buffers.
        pDataBuffer  = NULL;
        pExtraBuffer = NULL;
        for(i = 1; i < 4; i++)
        {

            if(pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
            {
                pDataBuffer = &Buffers[i];
				if (fVerbose >= 2)
					printf("Buffers[%d].BufferType = SECBUFFER_DATA\n",i);

            }
            if(pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
            {
                pExtraBuffer = &Buffers[i];
            }
        }

        // Display or otherwise process the decrypted data.
        if(pDataBuffer)
        {
			cbDataReceived += pDataBuffer->cbBuffer;
			if (fVerbose >= 1)
			printf("Decrypted data: %d bytes\n", pDataBuffer->cbBuffer);

			if (fVerbose >= 2)
				{
					PrintHexDump(pDataBuffer->cbBuffer, (PBYTE)pDataBuffer->pvBuffer);
					printf("\n");
				}
//////////////////////////////////////////			  
			if (Save_XML && kol_while>2)
			{
				try 
				{
					fwrite((PBYTE)pDataBuffer->pvBuffer, pDataBuffer->cbBuffer, 1, fp);
					printf(" -> SAVE DECRYPT DATA TO FILE: %20s \n\n", chSaveFile);
				}
				catch (...)
				{
					//printf("\n\n  ---- ERORR  -----  SAVE TO FILE: %20s \n\n", chSaveFile);
					snprintf(logText, sizeof(logText), " ---- ERORR  -----  SAVE TO FILE: %20s \n\n", chSaveFile);
					LogFile->WriteLine(logText);

				}
			}

/////////////////////////////////////////
        }

        // Move any "extra" data to the input buffer.
        if(pExtraBuffer)
        {
            MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            cbIoBuffer = pExtraBuffer->cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }

        if(scRet == SEC_I_RENEGOTIATE)
        {
            // The server wants to perform another handshake
            // sequence.

            printf("Server requested renegotiate!\n");

            scRet = ClientHandshakeLoop(Socket, 
                                        phCreds, 
                                        phContext, 
                                        FALSE, 
                                        &ExtraBuffer);
            if(scRet != SEC_E_OK)
            {
                return scRet;
            }

            // Move any "extra" data to the input buffer.
            if(ExtraBuffer.pvBuffer)
            {
                MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                cbIoBuffer = ExtraBuffer.cbBuffer;
            }
        }
    }
	
	if (Save_XML)
	{
		fclose(fp);
		snprintf(logText, sizeof(logText), "\t данные записаны в файл: %s ", chSaveFile);
		LogFile->WriteLine(logText);
	}


    if (pbIoBuffer) 
	LocalFree (pbIoBuffer);

    return SEC_E_OK;
}






/*****************************************************************************/
static 
void
DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal)
{
    CHAR szName[1000];
    PCCERT_CONTEXT pCurrentCert;
    PCCERT_CONTEXT pIssuerCert;
    DWORD dwVerificationFlags;

    printf("\n");

    // display leaf name
    if(!CertNameToStr(pServerCert->dwCertEncodingType,
                      &pServerCert->pCertInfo->Subject,
                      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                      szName, sizeof(szName)))
    {
        //printf("**** Error 0x%x building subject name\n", GetLastError());
		snprintf(logText, sizeof(logText), "**** Error 0x%x building subject name", GetLastError());
		LogFile->WriteLine(logText);

    }
    if(fLocal)
    {
        //printf("Client subject: %s\n", szName);
		snprintf(logText, sizeof(logText), "\t Client subject: %s", szName);
		LogFile->WriteLine(logText);
    }
    else
    {
        //printf("Server subject: %s\n", szName);
		snprintf(logText, sizeof(logText), "\t Server subject: %s", szName);
		LogFile->WriteLine(logText);
    }
    if(!CertNameToStr(pServerCert->dwCertEncodingType,
                      &pServerCert->pCertInfo->Issuer,
                      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                      szName, sizeof(szName)))
    {
        //printf("**** Error 0x%x building issuer name\n", GetLastError());
		snprintf(logText, sizeof(logText), "**** Error 0x%x building issuer name", GetLastError());
		LogFile->WriteLine(logText);
    }
    if(fLocal)
    {
        //printf("Client issuer: %s\n", szName);
		snprintf(logText, sizeof(logText), "\t Client issuer: %s", szName);
		LogFile->WriteLine(logText);
    }
    else
    {
        //printf("Server issuer: %s\n\n", szName);
		snprintf(logText, sizeof(logText), "\t Server issuer: %s", szName);
		LogFile->WriteLine(logText);

    }


    // display certificate chain
    pCurrentCert = pServerCert;
    while(pCurrentCert != NULL)
    {
        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(pServerCert->hCertStore,
                                                        pCurrentCert,
                                                        NULL,
                                                        &dwVerificationFlags);
        if(pIssuerCert == NULL)
        {
            if(pCurrentCert != pServerCert)
            {
                CertFreeCertificateContext(pCurrentCert);
            }
            break;
        }

        if(!CertNameToStr(pIssuerCert->dwCertEncodingType,
                          &pIssuerCert->pCertInfo->Subject,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          szName, sizeof(szName)))
        {
            //printf("**** Error 0x%x building subject name\n", GetLastError());
			snprintf(logText, sizeof(logText), "**** Error 0x % x building subject name", GetLastError());
			LogFile->WriteLine(logText);

        }
        printf("CA subject: %s\n", szName);
        if(!CertNameToStr(pIssuerCert->dwCertEncodingType,
                          &pIssuerCert->pCertInfo->Issuer,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          szName, sizeof(szName)))
        {
            //printf("**** Error 0x%x building issuer name\n", GetLastError());
			snprintf(logText, sizeof(logText), "**** Error 0x%x building issuer name", GetLastError());
			LogFile->WriteLine(logText);

        }
        //printf("CA issuer: %s\n\n", szName);
		snprintf(logText, sizeof(logText), "\t CA issuer: %s\n", szName);
		LogFile->WriteLine(logText);


        if(pCurrentCert != pServerCert)
        {
            CertFreeCertificateContext(pCurrentCert);
        }
        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }
}





/*****************************************************************************/
static 
DWORD
VerifyServerCertificate(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags)
{
    HTTPSPolicyCallbackData  polHttps;
    CERT_CHAIN_POLICY_PARA   PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA          ChainPara;
    PCCERT_CHAIN_CONTEXT     pChainContext = NULL;

    DWORD   Status;
    PWSTR   pwszServerName;
    DWORD   cchServerName;

    if(pServerCert == NULL)
    {
        return (DWORD)SEC_E_WRONG_PRINCIPAL;
    }


    //
    // Convert server name to unicode.
    //

    if(pszServerName == NULL || strlen(pszServerName) == 0)
    {
        return (DWORD)SEC_E_WRONG_PRINCIPAL;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);
    pwszServerName = (PWSTR)LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
    if(pwszServerName == NULL)
    {
        return (DWORD)SEC_E_INSUFFICIENT_MEMORY;
    }
    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
    if(cchServerName == 0)
    {
        return (DWORD)SEC_E_WRONG_PRINCIPAL;
    }


    //
    // Build certificate chain.
    //

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);

    if(!CertGetCertificateChain(
                            NULL,
                            pServerCert,
                            NULL,
                            pServerCert->hCertStore,
                            &ChainPara,
                            CERT_CHAIN_CACHE_END_CERT,
                            NULL,
                            &pChainContext))
    {
        Status = GetLastError();
        //printf("Error 0x%x returned by CertGetCertificateChain!\n", Status);
		snprintf(logText, sizeof(logText), "****  Error 0x%x returned by CertGetCertificateChain!\n", Status);
		LogFile->WriteLine(logText);

        goto cleanup;
    }


    //
    // Validate certificate chain.
    // 

    ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType         = AUTHTYPE_SERVER;
    polHttps.fdwChecks          = dwCertFlags;
    polHttps.pwszServerName     = pwszServerName;

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize            = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if(!CertVerifyCertificateChainPolicy(
                            CERT_CHAIN_POLICY_SSL,
                            pChainContext,
                            &PolicyPara,
                            &PolicyStatus))
    {
        Status = GetLastError();
        //printf("Error 0x%x returned by CertVerifyCertificateChainPolicy!\n", Status);
		snprintf(logText, sizeof(logText), "**** Error 0x%x returned by CertVerifyCertificateChainPolicy!", Status);
		LogFile->WriteLine(logText);

        goto cleanup;
    }

    if(PolicyStatus.dwError)
    {
        Status = PolicyStatus.dwError;
        DisplayWinVerifyTrustError(Status); 
        goto cleanup;
    }


    Status = SEC_E_OK;

cleanup:

    if(pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    if (pwszServerName)
	LocalFree (pwszServerName);

    return Status;
}








/*****************************************************************************/
static
void
DisplayConnectionInfo(
    CtxtHandle *phContext)
{
    SECURITY_STATUS Status;
    SecPkgContext_ConnectionInfo ConnectionInfo;

    Status = g_SecurityFunc.QueryContextAttributes(phContext,
                                    SECPKG_ATTR_CONNECTION_INFO,
                                    (PVOID)&ConnectionInfo);
    if(Status != SEC_E_OK)
    {
        //printf("Error 0x%x querying connection info\n", Status);
		snprintf(logText, sizeof(logText), "**** Error 0x % x querying connection info", Status);
		LogFile->WriteLine(logText);
        return;
    }

    printf("\n");

    switch(ConnectionInfo.dwProtocol)
    {
        case SP_PROT_TLS1_CLIENT:
            printf("Protocol: TLS1\n");
            break;

        case SP_PROT_SSL3_CLIENT:
            printf("Protocol: SSL3\n");
            break;

        case SP_PROT_PCT1_CLIENT:
            printf("Protocol: PCT\n");
            break;

        case SP_PROT_SSL2_CLIENT:
            printf("Protocol: SSL2\n");
            break;

        default:
            printf("Protocol: 0x%x\n", ConnectionInfo.dwProtocol);
    }

    switch(ConnectionInfo.aiCipher)
    {
        case CALG_RC4: 
            printf("Cipher: RC4\n");
            break;

        case CALG_3DES: 
            printf("Cipher: Triple DES\n");
            break;

        case CALG_RC2: 
            printf("Cipher: RC2\n");
            break;

        case CALG_DES: 
        case CALG_CYLINK_MEK:
            printf("Cipher: DES\n");
            break;

        case CALG_SKIPJACK: 
            printf("Cipher: Skipjack\n");
            break;

        default: 
            printf("Cipher: 0x%x\n", ConnectionInfo.aiCipher);
    }

    printf("Cipher strength: %d\n", ConnectionInfo.dwCipherStrength);

    switch(ConnectionInfo.aiHash)
    {
        case CALG_MD5: 
            printf("Hash: MD5\n");
            break;

        case CALG_SHA: 
            printf("Hash: SHA\n");
            break;

        default: 
            printf("Hash: 0x%x\n", ConnectionInfo.aiHash);
    }

    printf("Hash strength: %d\n", ConnectionInfo.dwHashStrength);

    switch(ConnectionInfo.aiExch)
    {
        case CALG_RSA_KEYX: 
        case CALG_RSA_SIGN: 
            printf("Key exchange: RSA\n");
            break;

        case CALG_KEA_KEYX: 
            printf("Key exchange: KEA\n");
            break;

        case CALG_DH_EPHEM:
            printf("Key exchange: DH Ephemeral\n");
            break;

        default: 
            printf("Key exchange: 0x%x\n", ConnectionInfo.aiExch);
    }

    printf("Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
}








/*****************************************************************************/
static
void
GetNewClientCredentials(
    CredHandle *phCreds,
    CtxtHandle *phContext)
{
    CredHandle hCreds;
    SecPkgContext_IssuerListInfoEx IssuerListInfo;
    PCCERT_CHAIN_CONTEXT pChainContext;
    CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara;
    PCCERT_CONTEXT  pCertContext;
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;

    //
    // Read list of trusted issuers from schannel.
    //

    Status = g_SecurityFunc.QueryContextAttributes(phContext,
                                    SECPKG_ATTR_ISSUER_LIST_EX,
                                    (PVOID)&IssuerListInfo);
    if(Status != SEC_E_OK)
    {
        printf("Error 0x%x querying issuer list info\n", Status);
        return;
    }

    //
    // Enumerate the client certificates.
    //

    ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

    FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
    FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
    FindByIssuerPara.dwKeySpec = 0;
    FindByIssuerPara.cIssuer   = IssuerListInfo.cIssuers;
    FindByIssuerPara.rgIssuer  = IssuerListInfo.aIssuers;

    pChainContext = NULL;

    while(TRUE)
    {
        // Find a certificate chain.
        pChainContext = CertFindChainInStore(hMyCertStore,
                                             X509_ASN_ENCODING,
                                             0,
                                             CERT_CHAIN_FIND_BY_ISSUER,
                                             &FindByIssuerPara,
                                             pChainContext);
        if(pChainContext == NULL)
        {
            printf("Error 0x%x finding cert chain\n", GetLastError());
            break;
        }
        printf("\ncertificate chain found\n");

        // Get pointer to leaf certificate context.
        pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

        // Create schannel credential.
        SchannelCred.cCreds = 1;
        SchannelCred.paCred = &pCertContext;

        Status = g_SecurityFunc.AcquireCredentialsHandleA(
                            NULL,                   // Name of principal
                            UNISP_NAME_A,           // Name of package
                            SECPKG_CRED_OUTBOUND,   // Flags indicating use
                            NULL,                   // Pointer to logon ID
                            &SchannelCred,          // Package specific data
                            NULL,                   // Pointer to GetKey() func
                            NULL,                   // Value to pass to GetKey()
                            &hCreds,                // (out) Cred Handle
                            &tsExpiry);             // (out) Lifetime (optional)
        if(Status != SEC_E_OK)
        {
            printf("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);
            continue;
        }
        printf("\nnew schannel credential created\n");

        // Destroy the old credentials.
        g_SecurityFunc.FreeCredentialsHandle(phCreds);

        *phCreds = hCreds;

        break;
    }
}
    

