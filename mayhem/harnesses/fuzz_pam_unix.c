/*
 * pam_unix.so: password-hash verification (verify_pwd_hash: crypt(3) prefixes, the
 * in-tree md5_crypt / broken md5 / bigcrypt) and shadow aging checks
 * (check_shadow_expiry), plus module option parsing (_set_ctrl), through
 * pam_authenticate() + pam_acct_mgmt().
 * Input: <hash> NUL <password> NUL <aging> NUL <module options line>
 *   aging = "lastchg,min,max,warn,inact,expire" (decimal, missing fields = -1)
 *
 * The account lookup is mocked (environment, not target code): getpwnam_r() and
 * getspnam_r() for "pamfuzz" return entries carrying the fuzzed hash and aging
 * fields (/etc/passwd and /etc/shadow are not writable here, and pam_unix would
 * otherwise exec the setuid unix_chkpwd helper). The fuzz build enables
 * pam_unix-try-getspnam so the module reads the mocked shadow entry in-process.
 * PF_INTERPOSE: linked with -rdynamic so libpam's/the module's calls bind to these.
 */
#include "pam_fuzz_common.h"
#include <shadow.h>

static char *g_hash;
static long g_aging[6];

static int (*real_pw)(const char *, struct passwd *, char *, size_t, struct passwd **);
static int (*real_sp)(const char *, struct spwd *, char *, size_t, struct spwd **);

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen,
	       struct passwd **result)
{
	if (name && strcmp(name, "pamfuzz") == 0 && g_hash) {
		if (buflen < 64) {
			*result = NULL;
			return ERANGE;
		}
		char *p = buf;
		pwd->pw_name = strcpy(p, "pamfuzz"); p += 8;
		pwd->pw_passwd = strcpy(p, "x"); p += 2;
		pwd->pw_gecos = strcpy(p, "Fuzz"); p += 5;
		pwd->pw_dir = strcpy(p, "/nonexistent"); p += 13;
		pwd->pw_shell = strcpy(p, "/bin/sh");
		pwd->pw_uid = 4242;
		pwd->pw_gid = 4242;
		*result = pwd;
		return 0;
	}
	if (!real_pw)
		real_pw = (int (*)(const char *, struct passwd *, char *, size_t, struct passwd **))
			dlsym(RTLD_NEXT, "getpwnam_r");
	return real_pw(name, pwd, buf, buflen, result);
}

int getspnam_r(const char *name, struct spwd *sp, char *buf, size_t buflen,
	       struct spwd **result)
{
	if (name && strcmp(name, "pamfuzz") == 0 && g_hash) {
		size_t need = strlen(g_hash) + 16;
		if (buflen < need) {
			*result = NULL;
			return ERANGE;
		}
		sp->sp_namp = strcpy(buf, "pamfuzz");
		sp->sp_pwdp = strcpy(buf + 8, g_hash);
		sp->sp_lstchg = g_aging[0];
		sp->sp_min = g_aging[1];
		sp->sp_max = g_aging[2];
		sp->sp_warn = g_aging[3];
		sp->sp_inact = g_aging[4];
		sp->sp_expire = g_aging[5];
		sp->sp_flag = (unsigned long)-1;
		*result = sp;
		return 0;
	}
	if (!real_sp)
		real_sp = (int (*)(const char *, struct spwd *, char *, size_t, struct spwd **))
			dlsym(RTLD_NEXT, "getspnam_r");
	return real_sp(name, sp, buf, buflen, result);
}

static void parse_aging(const char *s)
{
	for (int i = 0; i < 6; i++)
		g_aging[i] = -1;
	for (int i = 0; i < 6 && *s; i++) {
		char *end;
		long v = strtol(s, &end, 10);
		if (end != s)
			g_aging[i] = v;
		s = strchr(end, ',');
		if (!s)
			break;
		s++;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	/* a shadow(5) password field cannot contain ':' or a newline */
	if (memchr(f, ':', n) || memchr(f, '\n', n) || n > 4096)
		return -1;
	char *hash = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	char *pass = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	char *aging = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	if (memchr(f, '\n', n) || memchr(f, '\r', n) || memchr(f, '\0', n) || n > 1024) {
		free(hash); free(pass); free(aging);
		return -1;
	}
	char *opts = pf_strndup(f, n);
	parse_aging(aging);
	g_hash = hash;
	pf_password = pass;
	char svc[2 * PATH_MAX + 2200];
	snprintf(svc, sizeof(svc),
		 "auth required " PF_MOD("pam_unix") " nodelay %s\n"
		 "account required " PF_MOD("pam_unix") " %s\n", opts, opts);
	pam_handle_t *pamh = pf_start(svc, "pamfuzz");
	if (pamh) {
		(void)pam_authenticate(pamh, 0);
		(void)pam_acct_mgmt(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_password = "fuzz-password";
	g_hash = NULL;
	free(hash); free(pass); free(aging); free(opts);
	pf_restore();
	return 0;
}
