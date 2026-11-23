/*
 * pam_succeed_if.so: condition-argument evaluator (evaluate, numeric/string/glob/
 * ingroup operators, evaluate_inlist) and libpam's module-argument tokenizer,
 * through pam_authenticate(). Input: <PAM_RHOST> NUL <PAM_TTY> NUL <module args>.
 * Args containing a newline are rejected: a newline ends the service-file line,
 * so the rest would be a new pam.d entry naming arbitrary (trusted) modules.
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
	if (memchr(f, '\n', n) || memchr(f, '\r', n) || memchr(f, '\0', n) || n > 4096) {
		free(rhost);
		free(tty);
		return -1;
	}
	char *args = pf_strndup(f, n);
	size_t svclen = n + PATH_MAX;
	char *svc = malloc(svclen);
	snprintf(svc, svclen, "auth required " PF_MOD("pam_succeed_if") " %s\n", args);
	pam_handle_t *pamh = pf_start(svc, pf_user);
	if (pamh) {
		if (*rhost)
			pam_set_item(pamh, PAM_RHOST, rhost);
		if (*tty)
			pam_set_item(pamh, PAM_TTY, tty);
		(void)pam_authenticate(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	free(svc);
	free(args);
	free(rhost);
	free(tty);
	pf_restore();
	return 0;
}
