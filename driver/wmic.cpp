#include "wmic.hpp"
#include "dbglog.hpp"

namespace spoofer::wmic
{
	UINT64 WmipInUseRegEntryHead = 0;

	DRIVER_STATUS cripple()
	{
		LOG("WMIC cripple skipped for system stability");
		return DRIVER_STATUS::SUCCESS;
	}
}
