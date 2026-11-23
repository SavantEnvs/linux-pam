/*
 * pam_faillock.so: faillock.conf parser (read_config_file, set_conf_opt) and the
 * binary tally-file reader/updater (read_tally, update_tally, check_tally),
 * through pam_authenticate() on a preauth/authfail/authsucc stack as in
 * upstream's tst-pam_faillock-retval.c. Input: <faillock.conf> NUL <tally file>.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	const char *conf = pf_write("faillock.conf", f, n);
	char tdir[PATH_MAX], tname[PATH_MAX + 300];
	snprintf(tdir, sizeof(tdir), "%s/tally", pf_dir);
	if (mkdir(tdir, 0700) != 0 && errno != EEXIST)
		pf_die("mkdir tally");
	snprintf(tname, sizeof(tname), "tally/%s", pf_user);
	f = pf_field(&p, &left, &n);
	pf_write(tname, f, n);
	char svc[6 * PATH_MAX];
	snprintf(svc, sizeof(svc),
		 "auth requisite " PF_MOD("pam_faillock") " conf=%s dir=%s preauth even_deny_root\n"
		 "auth [default=die] " PF_MOD("pam_faillock") " conf=%s dir=%s authfail even_deny_root\n"
		 "auth sufficient " PF_MOD("pam_faillock") " conf=%s dir=%s authsucc even_deny_root\n",
		 conf, tdir, conf, tdir, conf, tdir);
	pam_handle_t *pamh = pf_start(svc, pf_user);
	if (pamh) {
		(void)pam_authenticate(pamh, 0);
		(void)pam_acct_mgmt(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_restore();
	return 0;
}
