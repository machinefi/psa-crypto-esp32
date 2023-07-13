#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

	bool global_data_is_initialized(void);
	void reset_global_data(void);
	void crypto_slot_management_reset_global_data(void);

#ifdef __cplusplus
}
#endif