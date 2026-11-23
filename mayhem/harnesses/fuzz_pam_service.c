/*
 * libpam's pam.d service-file parser (libpam/pam_handlers.c _pam_parse_conf_file,
 * include/substack handling, control-flag parsing; libpam_internal/pam_line.c;
 * pam_misc.c argv tokenizer) through pam_start_confdir(), then the dispatcher.
 *
 * Input: up to three NUL-separated files: "svc" (the service pam_start opens) and
 * "a", "b" which svc may reach with include/substack/@include.
 * Inputs containing '/' are rejected: a module path containing '/' is dlopen()ed
 * as code (pam.d(5): the module path is trusted, executable configuration), and
 * relative names resolve under the (uninstalled) securedir, so no module loads.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	if (memchr(data, '/', size))
		return -1;
	const uint8_t *p = data;
	size_t left = size, n;
	const uint8_t *f;
	static const char *names[] = { "svc", "a", "b" };
	for (int i = 0; i < 3; i++) {
		f = pf_field(&p, &left, &n);
		pf_write(names[i], f, n);
	}
	pam_handle_t *pamh = NULL;
	if (pam_start_confdir("svc", pf_user, &pf_pam_conv, pf_dir, &pamh) == PAM_SUCCESS) {
		void (*delay)(int, unsigned, void *) = pf_no_delay;
		pam_set_item(pamh, PAM_FAIL_DELAY, (const void *)delay);
		(void)pam_authenticate(pamh, 0);
		(void)pam_acct_mgmt(pamh, 0);
		(void)pam_open_session(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_restore();
	return 0;
}
