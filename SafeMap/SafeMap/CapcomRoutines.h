#pragma once
uintptr_t get_kernel_module(const std::string_view kmodule);
uintptr_t get_system_routine_internal(const std::wstring& name);
uintptr_t get_export(uintptr_t base, const char* name);