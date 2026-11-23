/*
 * pam_access.so: access.conf parser and matchers (login_access, list_match,
 * user/group/from/network matching) through pam_acct_mgmt().
 * Input: <PAM_RHOST> NUL <PAM_TTY> NUL <access.conf>. nodns keeps it off the network.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	char *rhost = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	char *tty = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	const char *conf = pf_write("access.conf", f, n);
	char svc[2 * PATH_MAX];
	snprintf(svc, sizeof(svc),
		 "account required " PF_MOD("pam_access") " accessfile=%s nodns\n", conf);
	pam_handle_t *pamh = pf_start(svc, pf_user);
	if (pamh) {
		if (*rhost)
			pam_set_item(pamh, PAM_RHOST, rhost);
		if (*tty)
			pam_set_item(pamh, PAM_TTY, tty);
		(void)pam_acct_mgmt(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	free(rhost);
	free(tty);
	pf_restore();
	return 0;
}
