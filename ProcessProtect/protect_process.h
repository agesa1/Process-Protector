#pragma once
#include <ntifs.h>

struct ProcessProtectArgs {
	size_t pid;
};

struct ProcessHideArgs {
	size_t pid;
};

struct ProtectProcessEntry {
	ProcessProtectArgs args;
	SINGLE_LIST_ENTRY next;
	LIST_ENTRY original_links;
	BOOLEAN is_hidden;
};

extern SINGLE_LIST_ENTRY* g_protected_processes;

NTSTATUS protect_process(const ProcessProtectArgs& args);

NTSTATUS hide_process(size_t pid);

NTSTATUS unhide_process(size_t pid);

NTSTATUS register_protectors();