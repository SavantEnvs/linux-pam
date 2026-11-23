/*
 * pam_group.so: group.conf parser (read_field, logic_field, is_same wildcard
 * matching, check_time, mkgrplist) through pam_setcred(PAM_ESTABLISH_CRED).
 * pam_group reads the fixed path SCONFIG_DIR/group.conf; the fuzz build sets
 * sconfigdir to this process's scratch directory (see pf_init), where this
 * harness writes it.
 * Input: <PAM_TTY> NUL <group.conf>.
 */
#include "pam_fuzz_common.h"

#ifndef PAM_FUZZ_SCONF_FD
#error "PAM_FUZZ_SCONF_FD must match the build's -Dsconfigdir=/proc/self/fd/<fd>"
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	char *tty = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	(void)pf_write("group.conf", f, n);
	pam_handle_t *pamh = pf_start("auth required " PF_MOD("pam_group") "\n", pf_user);
	if (pamh) {
		if (*tty)
			pam_set_item(pamh, PAM_TTY, tty);
		(void)pam_setcred(pamh, PAM_ESTABLISH_CRED);
		pam_end(pamh, PAM_SUCCESS);
	}
	free(tty);
	pf_restore();
	return 0;
}
