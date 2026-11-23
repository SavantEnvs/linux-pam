/*
 * Known-answer checks of libpam + modules through the public API, for mayhem/test.sh.
 * Prints one "name=value" line per check; test.sh diffs the output with expected.txt.
 * Usage: pam_oracle <modules dir> <scratch dir>
 */
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>

static int conv(int n, const struct pam_message **m, struct pam_response **r, void *a)
{
	(void)n; (void)m; (void)r; (void)a;
	return PAM_CONV_ERR;
}
static const struct pam_conv pconv = { conv, NULL };
static const char *moddir, *dir;
static char user[256];

static void wfile(const char *name, const char *text)
{
	char path[4096];
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	FILE *fp = fopen(path, "w");
	if (!fp) { perror(path); exit(2); }
	fputs(text, fp);
	fclose(fp);
}

static pam_handle_t *start(const char *svc)
{
	pam_handle_t *pamh = NULL;
	wfile("svc", svc);
	if (pam_start_confdir("svc", user, &pconv, dir, &pamh) != PAM_SUCCESS) {
		printf("pam_start=failed\n");
		exit(3);
	}
	return pamh;
}

int main(int argc, char **argv)
{
	if (argc != 3) return 2;
	moddir = argv[1]; dir = argv[2];
	struct passwd *pw = getpwuid(geteuid());
	snprintf(user, sizeof(user), "%s", pw ? pw->pw_name : "root");
	char svc[8192];

	/* pam_env: DEFAULT, ${VAR} expansion, envfile */
	wfile("env.conf", "FOO DEFAULT=bar\nBAZ DEFAULT=${FOO}-x\nQUX OVERRIDE=\"two words\"\n");
	wfile("environment", "ENVF=fromfile\n# comment\nexport EXP=1\n");
	snprintf(svc, sizeof(svc), "session required %s/pam_env/pam_env.so conffile=%s/env.conf envfile=%s/environment user_readenv=0\n", moddir, dir, dir);
	pam_handle_t *pamh = start(svc);
	printf("pam_env.open_session=%d\n", pam_open_session(pamh, 0));
	const char *keys[] = { "FOO", "BAZ", "QUX", "ENVF", "EXP", "MISSING" };
	for (unsigned i = 0; i < sizeof(keys) / sizeof(*keys); i++) {
		const char *v = pam_getenv(pamh, keys[i]);
		printf("env.%s=%s\n", keys[i], v ? v : "(null)");
	}
	pam_putenv(pamh, "FOO");
	printf("env.FOO.after_delete=%s\n", pam_getenv(pamh, "FOO") ? "set" : "(null)");
	pam_end(pamh, PAM_SUCCESS);

	/* pam_time: a rule that denies this service to everyone on any day */
	wfile("time.conf", "svc ; * ; * ; !Al0000-2400\n");
	snprintf(svc, sizeof(svc), "account required %s/pam_time/pam_time.so conffile=%s/time.conf\n", moddir, dir);
	pamh = start(svc);
	pam_set_item(pamh, PAM_TTY, "tty1");
	printf("pam_time.deny_all=%s\n", pam_strerror(pamh, pam_acct_mgmt(pamh, 0)));
	pam_end(pamh, PAM_SUCCESS);
	wfile("time.conf", "svc ; * ; * ; Al0000-2400\n");
	pamh = start(svc);
	pam_set_item(pamh, PAM_TTY, "tty1");
	printf("pam_time.allow_all=%s\n", pam_strerror(pamh, pam_acct_mgmt(pamh, 0)));
	pam_end(pamh, PAM_SUCCESS);

	/* pam_access: deny from one host, allow the rest */
	wfile("access.conf", "-:ALL:10.1.2.3\n+:ALL:ALL\n");
	snprintf(svc, sizeof(svc), "account required %s/pam_access/pam_access.so accessfile=%s/access.conf nodns\n", moddir, dir);
	const char *hosts[] = { "10.1.2.3", "10.9.9.9" };
	for (int i = 0; i < 2; i++) {
		pamh = start(svc);
		pam_set_item(pamh, PAM_RHOST, hosts[i]);
		printf("pam_access.%s=%s\n", hosts[i], pam_strerror(pamh, pam_acct_mgmt(pamh, 0)));
		pam_end(pamh, PAM_SUCCESS);
	}

	/* pam_succeed_if: numeric and string conditions */
	const char *conds[] = { "uid >= 0", "uid < 0", "user = nosuchuser-xyz", "service in svc:other" };
	for (int i = 0; i < 4; i++) {
		snprintf(svc, sizeof(svc), "auth required %s/pam_succeed_if/pam_succeed_if.so quiet %s\n", moddir, conds[i]);
		pamh = start(svc);
		printf("pam_succeed_if[%s]=%s\n", conds[i], pam_strerror(pamh, pam_authenticate(pamh, 0)));
		pam_end(pamh, PAM_SUCCESS);
	}

	/* libpam stack: include + control flags */
	snprintf(svc, sizeof(svc), "auth [success=1 default=ignore] %s/pam_deny/pam_deny.so\nauth include inc\n", moddir);
	{
		char inc[4096];
		snprintf(inc, sizeof(inc), "auth required %s/pam_permit/pam_permit.so\n", moddir);
		wfile("inc", inc);
	}
	pamh = start(svc);
	printf("stack.include_permit=%s\n", pam_strerror(pamh, pam_authenticate(pamh, 0)));
	pam_end(pamh, PAM_SUCCESS);
	snprintf(svc, sizeof(svc), "auth requisite %s/pam_deny/pam_deny.so\nauth include inc\n", moddir);
	pamh = start(svc);
	printf("stack.requisite_deny=%s\n", pam_strerror(pamh, pam_authenticate(pamh, 0)));
	pam_end(pamh, PAM_SUCCESS);
	return 0;
}
