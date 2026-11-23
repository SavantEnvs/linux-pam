/*
 * pam_umask.so: GECOS-field option parser (setup_limits_from_gecos: umask=, pri=,
 * ulimit=) and umask string parsing, through pam_open_session().
 * Input: the GECOS field of the user "pamfuzz" NUL <module options line>.
 *
 * The passwd lookup is mocked (environment, not target code): getpwnam_r() for
 * "pamfuzz" returns an entry carrying the fuzzed GECOS (/etc/passwd is not writable
 * here); other names go to libc. umask()/setpriority()/setrlimit() effects are
 * contained: the latter two are mocked, umask is restored after each input.
 * PF_INTERPOSE: linked with -rdynamic so libpam's/the module's calls bind to these.
 */
#include "pam_fuzz_common.h"
#include <sys/resource.h>
#include <sys/syscall.h>

static char *g_gecos;

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen,
	       struct passwd **result)
{
	if (name && strcmp(name, "pamfuzz") == 0 && g_gecos) {
		size_t need = strlen(g_gecos) + 64;
		if (buflen < need) {
			*result = NULL;
			return ERANGE;
		}
		char *p = buf;
		pwd->pw_name = strcpy(p, "pamfuzz"); p += 8;
		pwd->pw_passwd = strcpy(p, "x"); p += 2;
		pwd->pw_gecos = strcpy(p, g_gecos); p += strlen(g_gecos) + 1;
		pwd->pw_dir = strcpy(p, "/nonexistent"); p += 13;
		pwd->pw_shell = strcpy(p, "/bin/sh");
		pwd->pw_uid = 4242;
		pwd->pw_gid = 4242;
		*result = pwd;
		return 0;
	}
	static int (*real)(const char *, struct passwd *, char *, size_t, struct passwd **);
	if (!real)
		real = (int (*)(const char *, struct passwd *, char *, size_t, struct passwd **))
			dlsym(RTLD_NEXT, "getpwnam_r");
	return real(name, pwd, buf, buflen, result);
}

/*
 * Uninstrumented: the sanitizer runtime calls setrlimit() during its own init, before
 * shadow memory exists. Outside a PAM call the real syscall runs.
 */
static volatile int pf_in_pam;

__attribute__((disable_sanitizer_instrumentation))
int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim)
{
	if (!pf_in_pam)
		return (int)syscall(SYS_prlimit64, 0, (int)resource, rlim, NULL);
	if (rlim && rlim->rlim_cur > rlim->rlim_max) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/* libpam's build uses _FILE_OFFSET_BITS=64, which redirects setrlimit() to this. */
__attribute__((disable_sanitizer_instrumentation))
int setrlimit64(__rlimit_resource_t resource, const struct rlimit64 *rlim)
{
	if (!pf_in_pam)
		return (int)syscall(SYS_prlimit64, 0, (int)resource, rlim, NULL);
	if (rlim && rlim->rlim_cur > rlim->rlim_max) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

__attribute__((disable_sanitizer_instrumentation))
int setpriority(__priority_which_t which, id_t who, int prio)
{
	if (!pf_in_pam)
		return (int)syscall(SYS_setpriority, (int)which, who, prio);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	const uint8_t *p = data, *f;
	size_t left = size, n;
	f = pf_field(&p, &left, &n);
	/* a passwd(5) GECOS field cannot contain ':' or a newline */
	if (memchr(f, ':', n) || memchr(f, '\n', n))
		return -1;
	g_gecos = pf_strndup(f, n);
	f = pf_field(&p, &left, &n);
	if (memchr(f, '\n', n) || memchr(f, '\r', n) || memchr(f, '\0', n) || n > 1024) {
		free(g_gecos);
		g_gecos = NULL;
		return -1;
	}
	char *opts = pf_strndup(f, n);
	char svc[PATH_MAX + 1200];
	snprintf(svc, sizeof(svc), "session required " PF_MOD("pam_umask") " %s\n", opts);
	mode_t old = umask(022);
	pf_in_pam = 1;
	pam_handle_t *pamh = pf_start(svc, "pamfuzz");
	if (pamh) {
		(void)pam_open_session(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_in_pam = 0;
	umask(old);
	free(opts);
	free(g_gecos);
	g_gecos = NULL;
	pf_restore();
	return 0;
}
