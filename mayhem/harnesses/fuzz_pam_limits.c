/*
 * pam_limits.so: limits.conf parser (parse_config_file, process_limit, value and
 * uid/gid range parsing, @group/%group matching) through pam_open_session().
 * Input: limits.conf.
 *
 * setrlimit()/setpriority() are mocked (environment, not target code): applying
 * fuzzed limits to the fuzzer process itself would make later inputs depend on
 * earlier ones (a non-root process cannot raise a hard limit back) or kill it.
 * PF_INTERPOSE: linked with -rdynamic so the module's calls bind to these.
 */
#include "pam_fuzz_common.h"
#include <sys/resource.h>
#include <sys/syscall.h>

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
	const char *conf = pf_write("limits.conf", data, size);
	char svc[2 * PATH_MAX];
	snprintf(svc, sizeof(svc), "session required " PF_MOD("pam_limits") " conf=%s\n", conf);
	pf_in_pam = 1;
	pam_handle_t *pamh = pf_start(svc, pf_user);
	if (pamh) {
		(void)pam_open_session(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_in_pam = 0;
	pf_restore();
	return 0;
}
