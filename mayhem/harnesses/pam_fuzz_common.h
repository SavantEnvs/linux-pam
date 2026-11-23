/*
 * Shared helpers for the Linux-PAM fuzz harnesses (mayhem/harnesses/fuzz_*.c).
 *
 * Every harness drives libpam's PUBLIC API the way upstream's tst-*-retval.c tests do:
 * write the fuzzed config file(s) into a private scratch directory, write a pam.d
 * service file that loads one module by absolute path with options pointing at those
 * files, then pam_start_confdir() + the matching pam_* call + pam_end().
 *
 * State kept across iterations (on purpose): the scratch directory (its files are
 * rewritten before every pam_start) and the process's supplementary groups, which
 * are restored after each input when the process may change them (pam_group).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef PAM_FUZZ_COMMON_H
#define PAM_FUZZ_COMMON_H

#include <dlfcn.h>
#include <errno.h>
#include <glob.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <security/pam_appl.h>

#ifndef PAM_MODDIR
#error "PAM_MODDIR must point at the build tree's modules/ directory"
#endif

static char pf_dir[PATH_MAX];
static char pf_user[256];
static const char *pf_password = "fuzz-password";
static gid_t pf_groups[NGROUPS_MAX];
static int pf_ngroups = -1;

static void pf_die(const char *what)
{
	perror(what);
	abort();
}

static void pf_init(void)
{
	if (pf_dir[0])
		return;
	const char *tmp = getenv("TMPDIR");
	if (!tmp || !*tmp)
		tmp = "/tmp";
	snprintf(pf_dir, sizeof(pf_dir), "%s/pamfuzz.XXXXXX", tmp);
	if (!mkdtemp(pf_dir))
		pf_die("mkdtemp");
	struct passwd *pw = getpwuid(geteuid());
	snprintf(pf_user, sizeof(pf_user), "%s", pw ? pw->pw_name : "root");
	pf_ngroups = getgroups(NGROUPS_MAX, pf_groups);
#ifdef PAM_FUZZ_SCONF_FD
	/*
	 * Modules with a fixed config path (pam_group's SCONFIG_DIR/group.conf,
	 * pam_namespace's SCONFIG_DIR/namespace.conf) take no option to move it. The fuzz
	 * build sets sconfigdir to /proc/self/fd/PAM_FUZZ_SCONF_FD, and this descriptor
	 * names pf_dir, so that path is this process's private scratch directory and
	 * parallel fuzzer processes never share the file. (/proc is always mounted where
	 * ASan runs: it reads /proc/self/maps.)
	 */
	int dfd = open(pf_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		pf_die(pf_dir);
	if (dfd != PAM_FUZZ_SCONF_FD) {
		if (dup2(dfd, PAM_FUZZ_SCONF_FD) < 0)
			pf_die("dup2 sconfigdir");
		close(dfd);
	}
#endif
	/*
	 * Pin every module of the build in memory: pam_end() dlclose()s the modules it
	 * loaded, and an unmapped SanitizerCoverage-instrumented DSO makes libFuzzer
	 * touch freed counter memory. With an extra reference, dlclose() keeps them mapped.
	 */
	glob_t g;
	if (glob(PAM_MODDIR "/*/*.so", 0, NULL, &g) == 0) {
		for (size_t i = 0; i < g.gl_pathc; i++)
			(void)dlopen(g.gl_pathv[i], RTLD_NOW | RTLD_NODELETE);
		globfree(&g);
	}
}

/* Restore process-global state a module may have changed for the last input. */
static void pf_restore(void)
{
	if (pf_ngroups >= 0)
		(void)setgroups((size_t)pf_ngroups, pf_groups);
}

/* Writes len bytes to <pf_dir>/<name>; returns the absolute path in a static slot. */
static const char *pf_write(const char *name, const void *data, size_t len)
{
	static char paths[8][PATH_MAX];
	static int slot;
	char *path = paths[slot++ & 7];
	snprintf(path, PATH_MAX, "%s/%s", pf_dir, name);
	FILE *fp = fopen(path, "w");
	if (!fp)
		pf_die(path);
	if (len && fwrite(data, 1, len, fp) != len)
		pf_die("fwrite");
	if (fclose(fp) != 0)
		pf_die("fclose");
	return path;
}

/*
 * Splits the input into NUL-separated fields. Returns the next field (not
 * NUL-terminated, length in *flen); the last field takes the rest of the input.
 */
static const uint8_t *pf_field(const uint8_t **p, size_t *left, size_t *flen)
{
	const uint8_t *start = *p;
	const uint8_t *nul = *left ? memchr(start, 0, *left) : NULL;
	if (nul) {
		*flen = (size_t)(nul - start);
		*left -= *flen + 1;
		*p = nul + 1;
	} else {
		*flen = *left;
		*p = start + *left;
		*left = 0;
	}
	return start;
}

/* NUL-terminated copy of a field (caller frees). */
static char *pf_strndup(const uint8_t *s, size_t n)
{
	char *r = malloc(n + 1);
	if (!r)
		abort();
	memcpy(r, s, n);
	r[n] = '\0';
	return r;
}

static int pf_conv(int num_msg, const struct pam_message **msg,
		   struct pam_response **resp, void *appdata)
{
	(void)appdata;
	if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;
	struct pam_response *r = calloc((size_t)num_msg, sizeof(*r));
	if (!r)
		return PAM_BUF_ERR;
	for (int i = 0; i < num_msg; i++) {
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
		    msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
			r[i].resp = strdup(pf_password);
	}
	*resp = r;
	return PAM_SUCCESS;
}

static void pf_no_delay(int retval, unsigned usec_delay, void *appdata_ptr)
{
	(void)retval; (void)usec_delay; (void)appdata_ptr;
}

static const struct pam_conv pf_pam_conv = { pf_conv, NULL };

/* Writes the service file and starts a handle on it; NULL when pam_start fails. */
static pam_handle_t *pf_start(const char *service_text, const char *user)
{
	pf_write("svc", service_text, strlen(service_text));
	pam_handle_t *pamh = NULL;
	if (pam_start_confdir("svc", user, &pf_pam_conv, pf_dir, &pamh) != PAM_SUCCESS || !pamh)
		return NULL;
	void (*delay)(int, unsigned, void *) = pf_no_delay;
	pam_set_item(pamh, PAM_FAIL_DELAY, (const void *)delay);
	return pamh;
}

#define PF_MOD(name) PAM_MODDIR "/" name "/" name ".so"

#endif
