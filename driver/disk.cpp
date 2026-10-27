#include "spoofer.hpp"
#include "disk.hpp"
#include "util.hpp"
#include "pattern_scanner.hpp"
#include "sk_crypter.hpp"
#include "stealthmem.hpp"

#include <stdint.h>

#include "../driver_shellcode/kernel_context.hpp"
#include "../driver_shellcode/inline_util.hpp"

#include "dbglog.hpp"
#include "globals.hpp"
#include "hash.hpp"
#include "stack_string.hpp"
#include "native_imports.hpp"
#include "wmic.hpp"
#include <ntstrsafe.h>

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ata.h>
#include <scsi.h>
#include <ntddndis.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <classpnp.h>
#include <ntimage.h>

extern "C"
{
	extern POBJECT_TYPE* IoDriverObjectType;
}

typedef NTSTATUS(__fastcall* RU_REGISTER_INTERFACES)(PVOID device_extension);

#define STACK_DBGPRINT 0
#if (STACK_DBGPRINT==1)
#define STACK_LOG(x, ...) {STACK_STRING(stack_str, x); CALL_NO_RET(DbgPrint, stack_str, __VA_ARGS__);}
#else
#define STACK_LOG(x, ...)
#endif

__forceinline bool is_generated_serial(kernel_context* ctx, hash32_t serial_hash)
{
	for (uint16_t i = 0; i < ctx->subserial_count; ++i)
	{
		if (ctx->rndsubserial_hashes[i] == serial_hash)
			return true;
	}
	return false;
}

__forceinline char* get_spoofed_cache(kernel_context* ctx, hash32_t serial_hash)
{
	for (uint16_t i = 0; i < ctx->subserial_count; ++i)
	{
		if (ctx->subserial_cache[i] == serial_hash)
			return ctx->rndsubserial_cache[i];
	}
	return nullptr;
}

__forceinline void randomize_subserial(kernel_context* ctx, char* serial, size_t len, bool is_hex)
{
	const auto serial_hash = hash32(serial);

	if (is_generated_serial(ctx, serial_hash))
	{
		STACK_LOG("randomize_subserial: serial (%s) is already generated, ignore...", serial);
		return;
	}

	auto cached_serial = get_spoofed_cache(ctx, serial_hash);
	if (cached_serial != nullptr)
	{
		for (uint16_t i = 0; i < len; ++i)
			serial[i] = cached_serial[i];

		STACK_LOG("randomize_subserial: using cached serial %s", serial);
		return;
	}

	char spoofed_serial[21] = { 0 };
	for (auto i = 0u; i < len; ++i)
		spoofed_serial[i] = serial[i];

	auto& spoof_hash = globals::instance().args.SpoofHash;

	for (auto i = 0u; i < len; ++i)
	{
		if (inline_util::is_good_char(spoofed_serial[i]))
		{
			if (!is_hex)
			{
				spoofed_serial[i] = ((spoofed_serial[i] ^ spoof_hash[i % 16]) % 26) + 65;
			}
			else
			{
				auto number_or_letter = (spoofed_serial[i] ^ spoof_hash[i % 16]) % 2;
				if (number_or_letter == 0)
					spoofed_serial[i] = (spoofed_serial[i] ^ spoof_hash[i % 16]) % 6 + 97; // letter a-f
				else
					spoofed_serial[i] = (spoofed_serial[i] ^ spoof_hash[i % 16]) % 10 + 48; // number 0-9
			}
		}
	}

	// put into cache
	auto serial_index = ctx->subserial_count++;
	ctx->subserial_cache[serial_index] = serial_hash;
	for (uint16_t i = 0; i < len; ++i)
		ctx->rndsubserial_cache[serial_index][i] = spoofed_serial[i];

	ctx->rndsubserial_hashes[serial_index] = hash32(spoofed_serial);

	// and now finally overwrite
	for (auto i = 0u; i < len; ++i)
		serial[i] = spoofed_serial[i];
}

__forceinline void spoof_serial(kernel_context* ctx, char* serial, bool is_smart)
{
	size_t len = 20;
	char buf[50] = { 0 };
	bool is_serial_hex = true;

	if (is_smart)
	{
		is_serial_hex = false;
		len = 20;
		for (uint16_t i = 0; i < 20; ++i)
			buf[i] = serial[i];
	}
	else
	{
		is_serial_hex = true;
		for (len = 0; serial[len]; ++len)
		{
			if (!inline_util::is_hex(serial[len]))
				is_serial_hex = false;
		}
		if (len > 20)
			len = 20;

		for (uint16_t i = 0; i < len; ++i)
			buf[i] = serial[i];
	}

	buf[len] = 0;
	char split[2][20];
	__stosb((unsigned char*)split, 0, sizeof(split));

	for (auto i = 0u; i < len; ++i)
		split[i % 2][i / 2] = buf[i];

	randomize_subserial(ctx, split[0], (len + 1) / 2, is_serial_hex);
	randomize_subserial(ctx, split[1], len / 2, is_serial_hex);

	for (auto i = 0u; i < len; ++i)
		buf[i] = split[i % 2][i / 2];
	buf[len] = 0;

	if (is_smart)
	{
		for (uint16_t i = 0; i < 20; ++i)
			serial[i] = buf[i];
	}
	else
	{
		for (uint16_t i = 0; i < len + 1; ++i)
			serial[i] = buf[i];
	}
}

namespace spoofer::disk
{
	uint8_t scsi_num = 0;
	wchar_t scsi_drivers[3][25] = { 0 };

	// Spoof registry
	NTSTATUS SpoofRegistryStrValue(WCHAR* RegistryPath, WCHAR* KeyName)
	{
		HANDLE KeyHandle = NULL;
		OBJECT_ATTRIBUTES ObjAttr;
		UNICODE_STRING uRegistryPath;
		RtlInitUnicodeString(&uRegistryPath, RegistryPath);

		InitializeObjectAttributes(&ObjAttr, &uRegistryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		NTSTATUS Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjAttr);
		if (NT_SUCCESS(Status))
		{
			UNICODE_STRING uKeyName;
			RtlInitUnicodeString(&uKeyName, KeyName);

			unsigned char info_buffer[256] = { 0 };
			auto FullInfo = (KEY_VALUE_FULL_INFORMATION*)info_buffer;
			ULONG FullInfoLen = 0;
			Status = ZwQueryValueKey(KeyHandle, &uKeyName, KeyValueFullInformation, FullInfo, sizeof(info_buffer), &FullInfoLen);
			if (NT_SUCCESS(Status) && FullInfo->DataLength > 0)
			{
				UNICODE_STRING userial_number;
				userial_number.Buffer = (wchar_t*)(info_buffer + FullInfo->DataOffset);
				userial_number.Length = (USHORT)(FullInfo->DataLength > 2 ? FullInfo->DataLength - sizeof(wchar_t) : FullInfo->DataLength);
				userial_number.MaximumLength = (USHORT)FullInfo->DataLength;

				ANSI_STRING serial_number = { 0 };
				if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&serial_number, &userial_number, TRUE)))
				{
					LOG("[registry] spoofing %s", serial_number.Buffer);
					spoof_serial((kernel_context*)get_ctx(), serial_number.Buffer, false);

					UNICODE_STRING spoofed_key = { 0 };
					if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&spoofed_key, &serial_number, TRUE)))
					{
						Status = ZwSetValueKey(
							KeyHandle,
							&uKeyName,
							0,
							REG_SZ,
							(PVOID)spoofed_key.Buffer,
							(ULONG)((wcslen(spoofed_key.Buffer) + 1) * sizeof(wchar_t))
						);
						RtlFreeUnicodeString(&spoofed_key);
					}
					RtlFreeAnsiString(&serial_number);
				}
			}

			ZwClose(KeyHandle);
		}

		return Status;
	}

	NTSTATUS GetRegistryStrValue(WCHAR* RegistryPath, WCHAR* KeyName, PUNICODE_STRING OutStr)
	{
		HANDLE KeyHandle = NULL;
		OBJECT_ATTRIBUTES ObjAttr;
		UNICODE_STRING uRegistryPath;
		RtlInitUnicodeString(&uRegistryPath, RegistryPath);

		InitializeObjectAttributes(&ObjAttr, &uRegistryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		NTSTATUS Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjAttr);
		if (NT_SUCCESS(Status))
		{
			UNICODE_STRING uKeyName;
			RtlInitUnicodeString(&uKeyName, KeyName);

			unsigned char info_buffer[256] = { 0 };
			auto FullInfo = (KEY_VALUE_FULL_INFORMATION*)info_buffer;
			ULONG FullInfoLen = 0;
			Status = ZwQueryValueKey(KeyHandle, &uKeyName, KeyValueFullInformation, FullInfo, sizeof(info_buffer), &FullInfoLen);
			if (NT_SUCCESS(Status))
			{
				RtlInitUnicodeString(OutStr, (wchar_t*)(info_buffer + FullInfo->DataOffset));
			}

			ZwClose(KeyHandle);
		}

		return Status;
	}

	DRIVER_STATUS SaveScsiDriver(int scsi_port)
	{
		if (scsi_num >= 3)
			return DRIVER_STATUS::PARTMGR_DRIVER_OBJECT_NOT_FOUND;

		wchar_t registry_path[110] = { 0 };
		_RtlStringCchPrintfW(registry_path, 110, skCrypt(L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d"), scsi_port);

		UNICODE_STRING driver_value = { 0 };
		if (NT_SUCCESS(GetRegistryStrValue(registry_path, skCrypt(L"Driver"), &driver_value)) && driver_value.Buffer)
		{
			wcsncpy(scsi_drivers[scsi_num], driver_value.Buffer, 24);
			scsi_drivers[scsi_num][24] = L'\0';
			LOG("Got registry value: %ws, %i", driver_value.Buffer, scsi_port);
			scsi_num++;
			return DRIVER_STATUS::SUCCESS;
		}

		return DRIVER_STATUS::STORAHCI_DRIVER_OBJECT_NOT_FOUND;
	}

	DRIVER_STATUS SpoofRegistry()
	{
		bool cleaned = false;
		for (uint32_t i = 0; i < 16; ++i)
		{
			bool port_saved = false;
			for (uint32_t j = 0; j < 8; ++j)
			{
				wchar_t registry_path[110] = { 0 };
				_RtlStringCchPrintfW(registry_path, 110, skCrypt(L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d\\Scsi Bus %d\\Target Id 0\\Logical Unit Id 0"), i, j);

				if (NT_SUCCESS(SpoofRegistryStrValue(registry_path, skCrypt(L"SerialNumber"))))
				{
					LOG("Spoofed registry values for i=%i,j=%i", i, j);
					cleaned = true;

					if (!port_saved)
					{
						SaveScsiDriver(i);
						LOG("MARKED DRIVER FOR HOOKING!");
						port_saved = true;
					}
				}
			}
		}

		return cleaned ? DRIVER_STATUS::SUCCESS : DRIVER_STATUS::NTOS_NOT_FOUND;
	}

	// RaidUnits
	DRIVER_STATUS SpoofRaidUnitsInternal(RU_REGISTER_INTERFACES RaidUnitRegisterInterfaces, BYTE RaidUnitExtension_SerialNumber_offset)
	{
		PDRIVER_OBJECT visitedDrivers[16] = { 0 };
		int visitedCount = 0;

		for (int p = 0; p < 32; ++p)
		{
			wchar_t portName[32];
			_RtlStringCchPrintfW(portName, 32, skCrypt(L"\\Device\\RaidPort%d"), p);
			UNICODE_STRING uPort;
			RtlInitUnicodeString(&uPort, portName);
			PFILE_OBJECT fileObj = nullptr;
			PDEVICE_OBJECT devObj = nullptr;

			if (NT_SUCCESS(IoGetDeviceObjectPointer(&uPort, FILE_READ_DATA, &fileObj, &devObj)))
			{
				if (devObj && devObj->DriverObject)
				{
					bool alreadyVisited = false;
					for (int v = 0; v < visitedCount; ++v)
					{
						if (visitedDrivers[v] == devObj->DriverObject)
						{
							alreadyVisited = true;
							break;
						}
					}

					if (!alreadyVisited && visitedCount < 16)
					{
						visitedDrivers[visitedCount++] = devObj->DriverObject;

						for (PDEVICE_OBJECT device = devObj->DriverObject->DeviceObject; device; device = device->NextDevice)
						{
							__try
							{
								if (device && FILE_DEVICE_DISK == device->DeviceType && device->DeviceExtension && MmIsAddressValid(device->DeviceExtension))
								{
									PSTRING serial = (PSTRING)((PBYTE)device->DeviceExtension + RaidUnitExtension_SerialNumber_offset);
									if (MmIsAddressValid(serial) && serial->Buffer && serial->Length > 0 && MmIsAddressValid(serial->Buffer))
									{
										char old_serial[50] = { 0 };
										inline_util::strncpy(old_serial, serial->Buffer, serial->Length < 49 ? serial->Length : 49);

										char serialBuf[50] = { 0 };
										inline_util::strncpy(serialBuf, serial->Buffer, serial->Length < 49 ? serial->Length : 49);

										auto ctx = (kernel_context*)get_ctx();
										spoof_serial(ctx, serialBuf, false);
										LOG("[RAID] spoofing %s to %s", old_serial, serialBuf);
										inline_util::strncpy(serial->Buffer, serialBuf, serial->Length);

										if (MmIsAddressValid((PBYTE)device->DeviceExtension + 0x7C8))
										{
											*(int*)((PBYTE)device->DeviceExtension + 0x7C8) = 0;
										}

										if (RaidUnitRegisterInterfaces)
										{
											RaidUnitRegisterInterfaces(device->DeviceExtension);
										}
									}
								}
							}
							__except (EXCEPTION_EXECUTE_HANDLER)
							{
								LOG("[RAID] exception in port loop");
							}
						}
					}
				}

				if (fileObj)
					ObDereferenceObject(fileObj);
			}
		}

		return SUCCESS;
	}

	DRIVER_STATUS SpoofRaidUnits()
	{
		util::module storport = { 0 };
		if (!util::get_module(skCrypt("storport.sys"), storport) || !storport.base)
			return STORPORT_NOT_FOUND;

		RU_REGISTER_INTERFACES RaidUnitRegisterInterfaces = (RU_REGISTER_INTERFACES)(storport.base + 0x1BC54);
		BYTE RaidUnitExtension_SerialNumber_offset = 0x70;

		return SpoofRaidUnitsInternal(RaidUnitRegisterInterfaces, RaidUnitExtension_SerialNumber_offset);
	}

	DRIVER_STATUS spoof()
	{
		auto registry_status = SpoofRegistry();
		LOG("SpoofRegistry: %x", registry_status);
		for (uint16_t i = 0; i < scsi_num; ++i)
		{
			LOG("scsi_driver[%i]=%ws", i, scsi_drivers[i]);
		}
		if (!scsi_num)
			return DRIVER_STATUS::RAID_STORAHCI_DEVICES_ERROR;

		// Spoof Storport RaidUnits directly
		auto raidspoof_status = SpoofRaidUnits();
		LOG("SpoofRaidUnits: %x", raidspoof_status);

		return SUCCESS;
	}
}
