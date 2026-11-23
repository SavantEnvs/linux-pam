/*
 * pam_listfile.so: module-argument parser (item=, sense=, onerr=, apply=, file=,
 * list= and the item=/allow=/deny= shorthands), the list-file reader (match_file:
 * getline, negation, comments, glob vs exact precedence) and the inline list=
 * matcher, through pam_authenticate().
 * Input: <PAM_TTY> NUL <PAM_RHOST> NUL <PAM_RUSER> NUL <module args> NUL <list file>.
 * The fuzzed args follow "item=user sense=allow file=<list file>", so they may
 * override any of those.
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
	char *rhost = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	char *ruser = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	char *args = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	const char *list = pf_write("list", f, n);
	int ret = 0;
	/*
	 * The arguments go on one pam.d rule line: pam.conf(5) ends a rule at a newline
	 * (or continues it after a backslash), so a newline is not part of an argument;
	 * it would start a new, fuzzer-chosen rule, which fuzz_pam_service covers.
	 */
	if (strpbrk(args, "\r\n")) {
		ret = -1;
		goto out;
	}
	size_t svclen = strlen(args) + 2 * PATH_MAX;
	char *svc = malloc(svclen);
	if (!svc)
		abort();
	snprintf(svc, svclen,
		 "auth required " PF_MOD("pam_listfile") " item=user sense=allow file=%s %s\n",
		 list, args);
	pam_handle_t *pamh = pf_start(svc, pf_user);
	free(svc);
	if (pamh) {
		if (*tty)
			pam_set_item(pamh, PAM_TTY, tty);
		if (*rhost)
			pam_set_item(pamh, PAM_RHOST, rhost);
		if (*ruser)
			pam_set_item(pamh, PAM_RUSER, ruser);
		(void)pam_authenticate(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
out:
	free(tty);
	free(rhost);
	free(ruser);
	free(args);
	pf_restore();
	return ret;
}
