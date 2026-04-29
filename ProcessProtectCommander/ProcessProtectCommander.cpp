#include <iostream>
#include <string>
#include <Windows.h>

#define PROTECT_PROCESS_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_BUFFERED, FILE_WRITE_DATA)
#define HIDE_PROCESS_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1338, METHOD_BUFFERED, FILE_WRITE_DATA)
#define UNHIDE_PROCESS_IOCTL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1339, METHOD_BUFFERED, FILE_WRITE_DATA)

struct ProcessProtectArgs {
	size_t pid;
};

struct ProcessHideArgs {
	size_t pid;
};

HANDLE g_driver_handle = INVALID_HANDLE_VALUE;
size_t g_protected_pid = 0;
bool g_is_hidden = false;

bool open_driver() {
	g_driver_handle = CreateFileA("\\\\.\\ProcessProtect", GENERIC_ALL,
		0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	
	if (INVALID_HANDLE_VALUE == g_driver_handle) {
		DWORD error = GetLastError();
		std::cout << "Failed to open driver. Error: " << error << std::endl;
		std::cout << "Make sure driver is loaded and you have admin privileges" << std::endl;
		return false;
	}
	return true;
}

bool protect_process(size_t pid) {
	ProcessProtectArgs args = { pid };
	DWORD returned_bytes = 0;
	
	if (!DeviceIoControl(g_driver_handle, PROTECT_PROCESS_IOCTL, &args, sizeof(args),
		nullptr, 0, &returned_bytes, nullptr)) {
		std::cout << "Failed to protect process. Error: " << GetLastError() << std::endl;
		return false;
	}
	
	g_protected_pid = pid;
	std::cout << "Process " << pid << " is now PROTECTED" << std::endl;
	return true;
}

bool hide_process(size_t pid) {
	ProcessHideArgs args = { pid };
	DWORD returned_bytes = 0;
	
	if (!DeviceIoControl(g_driver_handle, HIDE_PROCESS_IOCTL, &args, sizeof(args),
		nullptr, 0, &returned_bytes, nullptr)) {
		std::cout << "Failed to hide process. Error: " << GetLastError() << std::endl;
		return false;
	}
	
	g_is_hidden = true;
	std::cout << "Process " << pid << " is now HIDDEN" << std::endl;
	return true;
}

bool unhide_process(size_t pid) {
	ProcessHideArgs args = { pid };
	DWORD returned_bytes = 0;
	
	if (!DeviceIoControl(g_driver_handle, UNHIDE_PROCESS_IOCTL, &args, sizeof(args),
		nullptr, 0, &returned_bytes, nullptr)) {
		std::cout << "Failed to unhide process. Error: " << GetLastError() << std::endl;
		return false;
	}
	
	g_is_hidden = false;
	std::cout << "Process " << pid << " is now VISIBLE" << std::endl;
	return true;
}

void show_menu() {
	std::cout << "\n========== ProcessProtect Commander ==========" << std::endl;
	std::cout << "Protected PID: " << (g_protected_pid ? std::to_string(g_protected_pid) : "None") << std::endl;
	std::cout << "Status: " << (g_is_hidden ? "HIDDEN" : "VISIBLE") << std::endl;
	std::cout << "==============================================" << std::endl;
	std::cout << "1. Protect a process" << std::endl;
	std::cout << "2. Hide protected process" << std::endl;
	std::cout << "3. Unhide protected process" << std::endl;
	std::cout << "4. Exit" << std::endl;
	std::cout << "Choice: ";
}

int main(int argc, char** argv) {
	
	if (!open_driver()) {
		return 1;
	}

	if (argc == 2) {
		size_t pid = static_cast<size_t>(std::stoi(argv[1]));
		protect_process(pid);
	}

	while (true) {
		show_menu();
		
		int choice;
		std::cin >> choice;
		
		if (std::cin.fail()) {
			std::cin.clear();
			std::cin.ignore(10000, '\n');
			std::cout << "Invalid input" << std::endl;
			continue;
		}

		switch (choice) {
		case 1: {
			std::cout << "Enter PID to protect: ";
			size_t pid;
			std::cin >> pid;
			protect_process(pid);
			break;
		}
		case 2: {
			if (g_protected_pid == 0) {
				std::cout << "No process protected yet" << std::endl;
			} else if (g_is_hidden) {
				std::cout << "Process is already hidden" << std::endl;
			} else {
				hide_process(g_protected_pid);
			}
			break;
		}
		case 3: {
			if (g_protected_pid == 0) {
				std::cout << "No process protected yet" << std::endl;
			} else if (!g_is_hidden) {
				std::cout << "Process is already visible" << std::endl;
			} else {
				unhide_process(g_protected_pid);
			}
			break;
		}
		case 4: {
			std::cout << "Exiting..." << std::endl;
			CloseHandle(g_driver_handle);
			return 0;
		}
		default:
			std::cout << "Invalid choice" << std::endl;
			break;
		}
	}

	return 0;
}

