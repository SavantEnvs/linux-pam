/*
 * pam_pwhistory.so: opasswd history-file parser (parse_entry, check_old_pass) and
 * pwhistory.conf parser, through pam_chauthtok() (PRELIM + UPDATE).
 * Input: <opasswd file> NUL <pwhistory.conf> NUL <new password>.
 * The history file is rewritten before each input, so a save by one input is not
 * seen by the next.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	const char *hist = pf_write("opasswd", f, n);
	f = pf_field(&p, &left, &n);
	const char *conf = pf_write("pwhistory.conf", f, n);
	f = pf_field(&p, &left, &n);
	char *pw = pf_strndup(f, n);
	pf_password = pw;
	char svc[4 * PATH_MAX];
	snprintf(svc, sizeof(svc),
		 "password required " PF_MOD("pam_pwhistory") " file=%s conf=%s enforce_for_root remember=5\n",
		 hist, conf);
	pam_handle_t *pamh = pf_start(svc, pf_user);
	if (pamh) {
		(void)pam_chauthtok(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_password = "fuzz-password";
	free(pw);
	pf_restore();
	return 0;
}
