#pragma once

#include "SKSE/SKSE.h"

#define ByteAt(addr) *reinterpret_cast<std::uint8_t*>(addr)

/// Declraing a pre_hook function allows Hook to receive a call before the main hook will be installed.
template <typename Hook>
concept pre_hook = requires {
	{
		Hook::pre_hook()
	};
};

/// Declraing a post_hook function allows Hook to receive a call immediately after the main hook will be installed.
template <typename Hook>
concept post_hook = requires {
	{
		Hook::post_hook()
	};
};

/// Fundamental concept for a hook.
/// A hook must have a static thunk function that will be written to a trampoline.
template <typename Hook>
concept hook = requires {
	{
		Hook::thunk
	};
};

/// Optionally Hook can define a static member named func that will contain the original function to chain the call.
/// static inline REL::Relocation<decltype(thunk)> func;
template <typename Hook>
concept chain_hook = requires {
	{
		Hook::func
	};
};

/// Basic Hook that writes a call (write_call<5>) instruction to a thunk.
/// This also supports writing to lea instructions, which store function addresses.
template <typename Hook>
concept call_hook = hook<Hook> && requires {
	{
		Hook::relocation
	} -> std::convertible_to<REL::ID>;
	{
		Hook::offset
	} -> std::convertible_to<std::size_t>;
};

/// A type that has a vtable to hook into.
/// vtable_hook can only be used with Targets that have a vtable.
template <typename Target>
concept has_vtable = requires {
	{
		Target::VTABLE
	};
};

/// Defines required fields for a valid vtable hook.
/// Note that providing a custom vtable index is optional, if ommited `0`th table will be used by default.
template <typename Hook>
concept vtable_hook = hook<Hook> && requires {
	{
		Hook::index
	} -> std::convertible_to<std::size_t>;
	requires(has_vtable<typename Hook::Target>);
};

/// Allows to provide a custom vtable index for a vtable hook.
/// Note that providing a custom vtable index is optional, if ommited `0`th table will be used by default.
template <typename Hook>
concept custom_vtable_index = requires {
	{
		Hook::vtable
	} -> std::convertible_to<std::size_t>;
};

// Optional properties of a hook.
namespace details
{
	template <typename Hook>
	constexpr std::size_t get_vtable()
	{
		if constexpr (custom_vtable_index<Hook>) {
			return Hook::vtable;  // Use the vtable if it exists
		} else {
			return 0;  // Default to 0 if vtable doesn't exist
		}
	}

	template <typename Hook>
	constexpr void set_func(std::uintptr_t func)
	{
		if constexpr (chain_hook<Hook>) {
			Hook::func = func;
		}
	}
}

namespace stl
{
	using namespace SKSE::stl;

	inline void print_bytes(std::uintptr_t address, size_t count)
	{
		logger::info("Bytes at address 0x{:X}:", address);
		std::string byteString = "";

		for (size_t i = 0; i < count; ++i) {
			uint8_t byte = ByteAt(address + i);
			byteString += fmt::format("{:02X} ", byte);

			if ((i + 1) % 8 == 0 || i == count - 1) {
				logger::info("  {}", byteString);
				byteString = "";
			}
		}
	}

	template <typename Hook>
	void analyze_potential_hooks(const std::vector<std::size_t>& validOffsets, std::uintptr_t baseAddress)
	{
		struct Pattern
		{
			std::string          name;
			std::vector<uint8_t> bytes;
			std::vector<bool>    mask; 
		};

		std::vector<Pattern> patterns;

		patterns.push_back({ "NULL outfit check",
			{ 0x48, 0x85, 0xC0 },  // TEST RAX, RAX (common null check)
			{ true, true, true } });

		patterns.push_back({ "GetActorBase call",
			{ 0x48, 0x8B, 0xCF, 0xE8 },  // MOV RCX, RDI followed by CALL
			{ true, true, true, true } });

		patterns.push_back({ "Sleep outfit branch",
			{ 0x84, 0xC0 },  // TEST AL, AL (checking boolean)
			{ true, true } });

		// For each valid offset
		for (auto offset : validOffsets) {
			std::uintptr_t address = baseAddress + offset;

			logger::info("Analyzing offset 0x{:X}:", offset);

			// Check for each pattern within a reasonable range
			const int searchRange = 50;  // Look 50 bytes before and after

			for (const auto& pattern : patterns) {
				for (int i = -searchRange; i <= searchRange; i++) {
					bool matched = true;

					// Try to match the pattern at this location
					for (size_t j = 0; j < pattern.bytes.size(); j++) {
						if (pattern.mask[j]) {
							if (ByteAt(address + i + j) != pattern.bytes[j]) {
								matched = false;
								break;
							}
						}
					}

					if (matched) {
						logger::info("  Found pattern '{}' at relative offset {:+d}",
							pattern.name, i);

						// Print some context around this match
						print_bytes(address + i - 8, 16 + pattern.bytes.size());
					}
				}
			}

			// Look for potential function boundaries
			// Common function prologue: 48 89 5C 24 (MOV [RSP+xx], RBX)
			// Common function epilogue: C3 (RET)
			for (int i = -searchRange; i <= searchRange; i++) {
				if (ByteAt(address + i) == 0x48 &&
					ByteAt(address + i + 1) == 0x89 &&
					ByteAt(address + i + 2) == 0x5C &&
					ByteAt(address + i + 3) == 0x24) {
					logger::info("  Potential function start at relative offset {:+d}", i);
				}

				if (ByteAt(address + i) == 0xC3) {
					logger::info("  Potential function end (RET) at relative offset {:+d}", i);
				}
			}
		}
	}

	template <typename Hook>
	void find_valid_hook_location()
	{
		static_assert(call_hook<Hook>, "find_valid_hook_location can only be used with call_hook types");

		const REL::Relocation<std::uintptr_t> rel{ Hook::relocation, Hook::offset };
		std::uintptr_t                        runtimeAddress = rel.address();
		std::uintptr_t                        baseAddress = runtimeAddress - Hook::offset;

		std::uintptr_t moduleBase = REL::Module::get().base();
		std::uintptr_t idStyleAddress = runtimeAddress - moduleBase;

		// Search a range before and after the expected offset
		const int         searchRange = 0x200;  // Adjust as needed
		const std::size_t expectedOffset = Hook::offset;

		logger::info("Scanning for valid hook locations near relocation+0x{:X}", expectedOffset);
		logger::info("Runtime base address: 0x{:X}", baseAddress);
		logger::info("Runtime target address: 0x{:X}", runtimeAddress);
		logger::info("Module base address: 0x{:X}", moduleBase);
		logger::info("SSE target address: 0x140{:X}", idStyleAddress);

		logger::info("Current hook location (offset 0x{:X}):", expectedOffset);
		print_bytes(runtimeAddress, 16);

		std::vector<std::size_t> validOffsets;

		for (int i = -searchRange; i <= searchRange; i += 1) {
			std::size_t    testOffset = expectedOffset + i;
			std::uintptr_t address = baseAddress + testOffset;

			uint8_t firstByte = ByteAt(address);
			uint8_t secondByte = ByteAt(address + 1);

			if (firstByte == 0xE8) {
				logger::info("Found CALL instruction at offset 0x{:X}", testOffset);
				//print_bytes(address, 8);
				validOffsets.push_back(testOffset);
			}
			else if (firstByte >= 0x48 && firstByte <= 0x4F && secondByte == 0x8D) {
				logger::info("Found LEA instruction with valid REX prefix at offset 0x{:X}", testOffset);
				//print_bytes(address, 8);
				validOffsets.push_back(testOffset);
			}
		}

		if (validOffsets.empty()) {
			logger::warn("No valid hook locations found in the search range!");
		} else {
			logger::info("Found {} potential valid hook locations:", validOffsets.size());

			for (auto offset : validOffsets) {
				std::uintptr_t address = baseAddress + offset;

				logger::info("Extended context for offset 0x{:X}:", offset);
				print_bytes(address - 32, 64);

				logger::info("Looking for 'MOV ECX, EDI' pattern near this address...");

				// Scan nearby for the MOV ECX, EDI instruction (8B CF)
				for (int i = -20; i < 20; i++) {
					if (ByteAt(address + i) == 0x8B && ByteAt(address + i + 1) == 0xCF) {
						std::uintptr_t hookIdAddress = address - moduleBase;

						logger::info("Found 'MOV ECX, EDI' at offset 0x{:X} (relative: {:+d}, SSE: 0x140{:X})",
							offset + i, i, hookIdAddress);
					}
				}
			}

			logger::info("Performing enhanced pattern analysis on valid hook candidates...");
			analyze_potential_hooks<Hook>(validOffsets, baseAddress);

		}
	}

	template <hook Hook>
	void write_thunk_call(std::uintptr_t a_src)
	{
		auto& trampoline = SKSE::GetTrampoline();
		SKSE::AllocTrampoline(14);

		details::set_func<Hook>(trampoline.write_call<5>(a_src, Hook::thunk));
	}

	template <has_vtable F, typename Hook>
	void write_vfunc()
	{
		REL::Relocation<std::uintptr_t> vtbl{ F::VTABLE[details::get_vtable<Hook>()] };
		details::set_func<Hook>(vtbl.write_vfunc(Hook::index, Hook::thunk));
	}

	template <vtable_hook Hook>
	void write_vfunc()
	{
		write_vfunc<typename Hook::Target, Hook>();
	}

	template <call_hook Hook>
	void write_thunk()
	{
		const REL::Relocation<std::uintptr_t> rel{ Hook::relocation, Hook::offset };
		std::uintptr_t                        sourceAddress = rel.address();

		// Debug print the first 16 bytes at the hook location
		logger::info("Attempting to hook at relocation+0x{:X} (Address: 0x{:X})",
			Hook::offset, sourceAddress);
		print_bytes(sourceAddress, 16);

		auto byteAddress = sourceAddress;
		auto opcode = ByteAt(byteAddress);

		if (opcode == 0xE8) {  // CALL instruction
			logger::info("Found CALL instruction (0xE8), proceeding with hook");
			write_thunk_call<Hook>(sourceAddress);
		} else {
			auto leaSize = 7;
			logger::info("First opcode byte: 0x{:02X}", opcode);

			// Check if we have a valid REX prefix
			if (opcode < 0x48 || opcode > 0x4F) {  // REX.W Must be present for a valid 64-bit address replacement.
				logger::error("Invalid REX prefix: 0x{:02X} is outside the range 0x48-0x4F", opcode);

				// Try to find valid hook locations nearby
				logger::warn("Attempting to find alternative hook locations...");
				find_valid_hook_location<Hook>();

				// Still fail with the original error
				stl::report_and_fail("Invalid hook location, lea instruction must use 64-bit register (first byte should be between 0x48 and 0x4F)"sv);
			}

			opcode = ByteAt(++byteAddress);
			logger::info("Second opcode byte: 0x{:02X}", opcode);

			if (opcode == 0x8D) {  // LEA instruction
				logger::info("Found LEA instruction (0x8D), proceeding with hook");
				auto op1 = ByteAt(++byteAddress);  // Get first operand byte.
				auto opAddress = byteAddress;
				// Store original displacement
				std::int32_t disp = 0;
				for (std::uint8_t i = 0; i < 4; ++i) {
					disp |= ByteAt(++byteAddress) << (i * 8);
				}

				assert(disp != 0);
				logger::info("Displacement value: 0x{:X}", disp);
				// write CALL on top of LEA
				// This will fill new displacement
				// 8D MM XX XX XX XX -> 8D E8 YY YY YY YY (where MM is the operand #1, XX is the old func, and YY is the new func)
				write_thunk_call<Hook>(opAddress);

				// Restore operand byte
				// Since we overwrote first operand of lea we need to write it back
				// 8D E8 YY YY YY YY -> 8D MM YY YY YY YY
				REL::safe_write(opAddress, op1);

				// Find original function and store it in the hook's func.
				details::set_func<Hook>(sourceAddress + leaSize + disp);
			} else {
				logger::error("Expected LEA instruction (0x8D), found 0x{:02X}", opcode);

				// Try to find valid hook locations nearby
				logger::warn("Attempting to find alternative hook locations...");
				find_valid_hook_location<Hook>();

				stl::report_and_fail("Invalid hook location, write_thunk can only be used for call or lea instructions"sv);
			}
		}
	}

	/// Installs given hook
	template <hook Hook>
	void install_hook()
	{
		using ThunkType = decltype(Hook::thunk);
		if constexpr (chain_hook<Hook>) {
			using FuncType = decltype(Hook::func);
			static_assert(std::is_same_v<REL::Relocation<ThunkType>, FuncType>, "Mismatching type of thunk and func. 'Use static inline REL::Relocation<decltype(thunk)> func;' to always match the type.");
		}

		if constexpr (pre_hook<Hook>) {
			Hook::pre_hook();
		}

		if constexpr (call_hook<Hook>) {
			stl::write_thunk<Hook>();
		} else if constexpr (vtable_hook<Hook>) {
			stl::write_vfunc<Hook>();
		} else {
			static_assert(false, "Unsupported hook type. Hook must target either call, lea or vtable");
		}

		if constexpr (post_hook<Hook>) {
			Hook::post_hook();
		}
	}
}

#undef ByteAt
