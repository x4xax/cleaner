#include <Windows.h>
#include "global.h"
#include <iostream>
#include <thread>
#pragma warning(disable: 6387)

int main()
{
	bool execute = true;
	BOOL win11 = utils::isWin11();
	std::thread killProces([execute]()
		{
			while (execute)
				clean::killProcs();
		}
	);
	std::cout << "Cleaning creds...\n";
	clean::cleanCreds();

	//std::cout << "Blocking hosts...\n";
	//clean::blockHosts();

	std::cout << "Cleaning registry...\n";
	clean::cleanReg();

	std::cout << "Flushing DNS...\n";
	clean::flushDns();
	if (win11)
	{
		std::cout << "Resetting Windows...\n";
		clean::resetApps();
	}

	std::cout << "Deleting Packages...\n";
	clean::delFolder();

	execute = false;

	killProces.detach();
    
	std::cout << "Cleaning complete\n";
	//MessageBox(NULL, (L"Cleaning complete", L"Task finished", MB_OK | MB_ICONINFORMATION));
	return 0;

}
