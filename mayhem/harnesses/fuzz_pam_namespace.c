/*
 * pam_namespace.so: namespace.conf parser (parse_config_file, process_line,
 * expand_variables for $USER/$HOME, method/option and user-list parsing) through
 * pam_open_session(). pam_namespace reads the fixed path SCONFIG_DIR/namespace.conf;
 * the fuzz build points sconfigdir at this process's scratch directory (see pf_init),
 * where this harness writes it.
 * Without CAP_SYS_ADMIN the later unshare(CLONE_NEWNS) fails, so no mounts happen.
 * Input: namespace.conf.
 */
#include "pam_fuzz_common.h"

#ifndef PAM_FUZZ_SCONF_FD
#error "PAM_FUZZ_SCONF_FD must match the build's -Dsconfigdir=/proc/self/fd/<fd>"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	(void)pf_write("namespace.conf", data, size);
	pam_handle_t *pamh = pf_start("session required " PF_MOD("pam_namespace") " ignore_config_error\n", pf_user);
	if (pamh) {
		(void)pam_open_session(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_restore();
	return 0;
}
