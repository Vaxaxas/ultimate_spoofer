#include "nic.hpp"
#include "util.hpp"
#include "sk_crypter.hpp"
#include "stealthmem.hpp"
#include "pattern_scanner.hpp"
#include "dbglog.hpp"
#include "spoofer.hpp"
#include "imports.hpp"
#include "hash.hpp"

#include "../driver_shellcode/kernel_context.hpp"

#include <ntstrsafe.h>

#include <pshpack1.h>
typedef struct _NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES {
	char pad[0x5c];
	uint16_t MacAddressLength; // 0x5c
	unsigned char PermanentMacAddress[32]; // 0x5e
	unsigned char CurrentMacAddress[32]; // 0x7e
} NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES, *PNDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;

typedef struct _NDIS_MINIPORT_BLOCK {
	char _pad[0xa98];
	PNDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES GeneralAttributes; // 0xa98
} NDIS_MINIPORT_BLOCK, *PNDIS_MINIPORT_BLOCK;

typedef struct _KSTRING {
	char _padding_0[0x10];
	WCHAR Buffer[1];
} KSTRING, *PKSTRING;

typedef struct _NDIS_FILTER_BLOCK {
	char _padding_0[0x8];
	struct _NDIS_FILTER_BLOCK* NextFilter; // 0x8
	char _padding_1[0x10];
	PNDIS_MINIPORT_BLOCK Miniport; // 0x20
	PKSTRING FilterInstanceName; // 0x28
	char _padding_2[0x40];
	struct _NDIS_FILTER_BLOCK* GlobalFilter; // 0x68
	struct _NDIS_FILTER_BLOCK* LowerFilter; // 0x70
	struct _NDIS_FILTER_BLOCK* HigherFilter; // 0x78
} NDIS_FILTER_BLOCK, *PNDIS_FILTER_BLOCK;
#include <poppack.h>

__forceinline void spoof_mac(uint8_t* buf, uint32_t len)
{
	if (len != 6)
	{
		LOG("len != 6: %i", len);
		return;
	}

	LOG("spoof_mac: (len: %i), MAC: %02X-%02X-%02X-%02X-%02X-%02X", len,
		buf[0], buf[1],
		buf[2], buf[3],
		buf[4], buf[5]);

	auto ctx = (kernel_context*)spoofer::get_ctx();
	auto hash = fnva1_buffer(buf, len);

	for (uint16_t i = 0; i < ctx->mac_count; ++i)
	{
		if (ctx->mac_spoofed_hash_cache[i] == hash)
		{
			LOG("spoof_mac: mac already spoofed!");
			return;
		}
	}

	for (uint16_t i = 0; i < ctx->mac_count; ++i)
	{
		if (ctx->mac_hash_cache[i] == hash)
		{
			auto spoofed_mac = ctx->mac_spoofed_cache[i];
			memcpy(buf, spoofed_mac, len);

			LOG("spoof_mac: mac spoofed from cache!");
			LOG("NEW_MAC: %02X-%02X-%02X-%02X-%02X-%02X",
				buf[0], buf[1],
				buf[2], buf[3],
				buf[4], buf[5]);
			return;
		}
	}

	uint8_t spoofed_mac[8] = { 0 };
	for (auto i = 0u; i < len; ++i)
	{
		spoofed_mac[i] = buf[i] ^ globals::instance().args.SpoofHash[i % 16];
	}

	// Ensure unicast and locally administered address (bit 0 = 0, bit 1 = 1)
	spoofed_mac[0] = (spoofed_mac[0] & 0xFE) | 0x02;

	// put into cache
	if (ctx->mac_count < 50)
	{
		auto index = ctx->mac_count++;
		ctx->mac_hash_cache[index] = hash;
		for (auto i = 0u; i < len; ++i)
			ctx->mac_spoofed_cache[index][i] = spoofed_mac[i];
		ctx->mac_spoofed_hash_cache[index] = fnva1_buffer(spoofed_mac, len);
	}

	memcpy(buf, spoofed_mac, len);
	LOG("NEW_MAC: %02X-%02X-%02X-%02X-%02X-%02X",
		buf[0], buf[1],
		buf[2], buf[3],
		buf[4], buf[5]);
}

namespace spoofer::nic
{
	DRIVER_STATUS spoof()
	{
		util::module ndis = { 0 };
		if (!util::get_module(skCrypt("ndis.sys"), ndis) && !util::get_module(skCrypt("NDIS.SYS"), ndis))
		{
			LOG("ndis.sys not found");
			return NDIS_NOT_FOUND;
		}

		auto ctx = (kernel_context*)spoofer::get_ctx();
		ctx->mac_count = 0;

		PNDIS_FILTER_BLOCK ndisGlobalFilterList = nullptr;
		if (ndis.base)
		{
			ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK*)(ndis.base + 0x000E54D8);
		}

		if (!ndisGlobalFilterList)
		{
			auto patternMatch = (PNDIS_FILTER_BLOCK)PATTERN_FIND_CODE("\x40\x8A\xF0\x48\x8B\x05");
			if (patternMatch)
			{
				patternMatch = (PNDIS_FILTER_BLOCK)((uint8_t*)patternMatch + 3);
				ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK*)((uint8_t*)patternMatch + 7 + *(uint32_t*)((uint8_t*)patternMatch + 3));
			}
		}

		if (!ndisGlobalFilterList)
			return NDIS_FILTER_NOT_FOUND;

		LOG("ndisGlobalFilterList: %llx", ndisGlobalFilterList);
		LOG("Handling NDIS adapters...");
		uint32_t count = 0;

		auto process_filter = [&](PNDIS_FILTER_BLOCK f) {
			if (!f || !MmIsAddressValid(f))
				return;

			if (MmIsAddressValid(&f->Miniport) && f->Miniport && MmIsAddressValid(f->Miniport))
			{
				auto miniport = (uint8_t*)f->Miniport;

				// 1. IfBlock directly referenced by ndis!ndisOidPreEthAddress for OID_802_3_PERMANENT_ADDRESS
				__try {
					if (MmIsAddressValid(miniport + 0xFC8))
					{
						uint8_t* ifBlock = *(uint8_t**)(miniport + 0xFC8);
						if (ifBlock && MmIsAddressValid(ifBlock) && MmIsAddressValid(ifBlock + 0x488 + 6))
						{
							uint16_t curLen = *(uint16_t*)(ifBlock + 0x464);
							uint16_t permLen = *(uint16_t*)(ifBlock + 0x486);
							if (curLen == 6 && permLen == 6)
							{
								spoof_mac(ifBlock + 0x466, 6);
								spoof_mac(ifBlock + 0x488, 6);
								++count;
							}
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {}

				// 2. Miniport GeneralAttributes
				__try {
					auto pGeneral = (PNDIS_MINIPORT_BLOCK)miniport;
					if (MmIsAddressValid(&pGeneral->GeneralAttributes) && pGeneral->GeneralAttributes && MmIsAddressValid(pGeneral->GeneralAttributes))
					{
						auto attr = pGeneral->GeneralAttributes;
						if (attr->MacAddressLength == 6)
						{
							spoof_mac(attr->PermanentMacAddress, 6);
							spoof_mac(attr->CurrentMacAddress, 6);
							++count;
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {}
			}
		};

		for (PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter && MmIsAddressValid(filter); filter = filter->NextFilter)
		{
			process_filter(filter);

			if (filter->LowerFilter && MmIsAddressValid(filter->LowerFilter))
			{
				process_filter(filter->LowerFilter);
			}

			if (filter->HigherFilter && MmIsAddressValid(filter->HigherFilter))
			{
				process_filter(filter->HigherFilter);
			}

			if (filter->GlobalFilter && MmIsAddressValid(filter->GlobalFilter))
			{
				process_filter(filter->GlobalFilter);
			}
		}

		LOG("handled %d MACs", count);
		return SUCCESS;
	}
}
