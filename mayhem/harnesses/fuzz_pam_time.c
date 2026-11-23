/*
 * pam_time.so: time.conf parser (read_field, logic_field, is_same, check_time)
 * through pam_acct_mgmt(). Input: <PAM_TTY> NUL <time.conf>.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	char *tty = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	const char *conf = pf_write("time.conf", f, n);
	char svc[2 * PATH_MAX];
	snprintf(svc, sizeof(svc),
		 "account required " PF_MOD("pam_time") " conffile=%s\n", conf);
	pam_handle_t *pamh = pf_start(svc, pf_user);
	if (pamh) {
		if (*tty)
			pam_set_item(pamh, PAM_TTY, tty);
		(void)pam_acct_mgmt(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	free(tty);
	pf_restore();
	return 0;
}
