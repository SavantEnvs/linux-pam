/*
 * libpam environment API: pam_putenv (add/replace/delete), pam_getenv,
 * pam_getenvlist (libpam/pam_env.c). Input: NUL-separated strings, each passed
 * to pam_putenv ("NAME=VALUE" sets, "NAME=" empties, "NAME" deletes) and then
 * looked up with pam_getenv.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	pam_handle_t *pamh = pf_start("session required " PF_MOD("pam_permit") "\n", pf_user);
	if (!pamh)
		abort(); /* a fixed, valid service file: pam_start must succeed */
	const uint8_t *p = data, *f;
	size_t left = size, n;
	int count = 0;
	while (left && count++ < 256) {
		f = pf_field(&p, &left, &n);
		char *s = pf_strndup(f, n);
		(void)pam_putenv(pamh, s);
		char *eq = strchr(s, '=');
		if (eq)
			*eq = '\0';
		const char *v = pam_getenv(pamh, s);
		if (v)
			(void)strlen(v);
		free(s);
	}
	char **env = pam_getenvlist(pamh);
	if (env) {
		for (char **e = env; *e; e++)
			free(*e);
		free(env);
	}
	pam_end(pamh, PAM_SUCCESS);
	return 0;
}
