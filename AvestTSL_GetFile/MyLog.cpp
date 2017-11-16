#include "stdafx.h"

#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

using namespace std;


class MyLog
{
private:
	string strLogFileName = "";
	bool isOk = false;
	int maxSizeLogKb = 1024;
	long sizeLogFile = 0;

public:

	MyLog(string file_name) //:logFile(file_name, ios_base::app | ios_base::ate)
	{
		// ������ ������ ������ ofstream ��� ������ � ��������� ��� � ������ file_name
		// app - ��� ���������� ������� � ����� �����; ate - ����������� ��������� � ����� ��� ����������� �������

		CheckFileName(file_name);
	}
	MyLog(string file_name, int max_size_logFile)
	{
		if (CheckFileName(file_name) && max_size_logFile > 0)
			 maxSizeLogKb = max_size_logFile;
	}

	~MyLog()
	{
	}
	/////////////////////////////////////////////////////////////////////////
	/// Get Set
	
	string GetLogFileName() { return strLogFileName; }
	bool GetIsOk() { return isOk; }
	int GetMaxSizeLogKb() { return maxSizeLogKb; }
	long GetSizeLogFile() { return sizeLogFile; }

	bool SetLogFileName(string file_name) { return CheckFileName(file_name); }
	bool SetMaxSizeLogKb(int maxSize_kb) 
	{ 
		if (isOk && maxSize_kb > 0) 
			maxSizeLogKb = maxSize_kb;
		else return false;
		return isOk; 
	}

	/////////////////////////////////////////////////////////////////////////
	bool CheckSizeLog()
	{
		if (isOk && sizeLogFile > (maxSizeLogKb * 1024))
		{
			long startPos = sizeLogFile / 3;
			return CutFile(strLogFileName, startPos);
		}
	}

	void SetMaxSizeLogFile(int max_size_logFile)
	{
		if (isOk && max_size_logFile > 0) maxSizeLogKb = max_size_logFile;
	}

	void BeginLog()
	{
		string text = "-----------------------------------------------------------";
		text = text + "\n>>> begin  "+ GetTimeNow() +"\n";
		WriteLine(text);
	}
	void EndLog()
	{
		string text = "";
		text = text + "\n<<< end    " + GetTimeNow() + "\n-----------------------------------------------------------";
		WriteLine(text);
	}


	void WriteLine(char* ch_text)
	{
		WriteLine(string(ch_text));
	}

	void WriteLine(string text)
	{
		cout << text << endl;

		ofstream fout(strLogFileName, ios_base::app | ios_base::ate);
		if (fout)
		{
			fout << text << endl;
			long file_size = fout.tellp();
			if (file_size > 0) sizeLogFile = file_size;
		}
		else
			isOk = false;

		fout.close();
		return;
	}



private:
	bool CheckFileName(string nameFile)
	{
		// ������ ������ ������ ofstream ��� ������ � ��������� ��� � ������ nameFile
		// app - ��� ���������� ������� � ����� �����; ate - ����������� ��������� � ����� ��� ����������� �������

		if (nameFile.length() > 4)
		{
			/// �������� �� ����������� ������ � ����
			ofstream logFile(nameFile, ios_base::app | ios_base::ate);
			if (logFile)
			{
				isOk = true;
				strLogFileName = nameFile;
				long file_size = logFile.tellp();
				if (file_size > 0) sizeLogFile = file_size;
			}

			logFile.close();
		}
		return isOk;
	}

	string GetTimeNow()
	{
		//setlocale(LC_ALL, "Russian_Russia.1251");
		/*
		%A � ������ �������� ��� ������
		%B � ������ �������� ������
		%d � ���� ������
		%Y � ��� � ���� 4 ����
		%H � ��� � 24-������� �������
		%M � ������
		%S � �������
		*/

		char buffer[20];
		time_t seconds = time(NULL);
		tm* timeinfo = localtime(&seconds);
		//char* format = "%A, %B %d, %Y %I:%M:%S";
		char* format = "%d.%m.%Y %H:%M:%S";
		strftime(buffer, 20, format, timeinfo);

		return string(buffer);
	}


	bool CutFile(string file_name, long start_new_position)
	{
		ifstream file_in;

		file_in.open(file_name);

		if (!file_in)
		{
			cerr << " -> ������, ���������� ������� ���� : " << file_name << endl;
			return false;
		}


		string line; //��� �������� ������
		string line_file_text; //��� �������� ������ �����


		while (getline(file_in, line))
		{
			long pos = file_in.tellg();

			cerr << "\t ������ : " << pos << endl;

			if (pos >= start_new_position || file_in.eof())
			{
				line_file_text.insert(line_file_text.size(), line);		/*�������� ������*/
				line_file_text.insert(line_file_text.size(), "\r\n");	/*�������� ������� �� ��������� ������*/
			}
		}

		file_in.close();

		//������ � line_file_text ����� ����������� ���������� ����� �����, ������ ����� ������������ ����

		std::ofstream file_out;

		file_out.open(file_name, std::ios::trunc | std::ios::binary); //������� � ��������

		file_out.write(line_file_text.c_str(), line_file_text.size()); //��������
		//file_out.clear();

		long last_pos = file_out.tellp();
		
		sizeLogFile = last_pos;

		file_out.close();

		return true;
	}


};

