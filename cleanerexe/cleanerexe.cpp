#include <Windows.h>
#include "global.h"
#include <iostream>
#include <thread>
#include <conio.h>
#pragma warning(disable: 6387)

int main()
{
	std::thread killProcs([]()
		{
			while (true)
				clean::killProcs();
		}
	);
	std::cout << "Cleaning creds...\n";
	clean::cleanCreds();

	std::cout << "Cleaning registry...\n";
	clean::cleanReg();

	std::cout << "Deleting Packages...\n";
	clean::delFolder();

	std::cout << "Spoofing MS Values...\n";
	spoof::SpoofSystemIds();

	killProcs.detach();
    
	std::cout << "\nCleaning complete\n\nDelete SSO_POP and virtualapp\n";
	_getch();
	return 0;
}
