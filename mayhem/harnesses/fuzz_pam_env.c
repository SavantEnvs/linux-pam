/*
 * pam_env.so: pam_env.conf parser (_parse_config_file/_parse_line/_expand_arg with
 * ${VAR} and @{HOME} expansion) and the environment-file parser, plus libpam's
 * pam_putenv/pam_getenvlist, through pam_setcred() and pam_open_session().
 * Input: <pam_env.conf> NUL <environment file>.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	const char *conf = pf_write("env.conf", f, n);
	f = pf_field(&p, &left, &n);
	const char *envf = pf_write("environment", f, n);
	char svc[4 * PATH_MAX];
	snprintf(svc, sizeof(svc),
		 "auth required " PF_MOD("pam_env") " conffile=%s envfile=%s user_readenv=0\n"
		 "session required " PF_MOD("pam_env") " conffile=%s envfile=%s user_readenv=0\n",
		 conf, envf, conf, envf);
	pam_handle_t *pamh = pf_start(svc, pf_user);
	if (pamh) {
		(void)pam_setcred(pamh, PAM_ESTABLISH_CRED);
		(void)pam_open_session(pamh, 0);
		char **env = pam_getenvlist(pamh);
		if (env) {
			for (char **e = env; *e; e++)
				free(*e);
			free(env);
		}
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_restore();
	return 0;
}
