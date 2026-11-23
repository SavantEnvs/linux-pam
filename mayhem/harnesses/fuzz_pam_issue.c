/*
 * pam_issue.so: issue-file reader with backslash-escape expansion
 * (read_issue_quoted: \d \t \s \n \u ...) and the raw reader (noesc), through
 * pam_authenticate(). Input: <mode byte> <issue file>; odd mode byte = noesc.
 */
#include "pam_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	if (size < 1)
		return -1;
	int noesc = data[0] & 1;
	const char *issue = pf_write("issue", data + 1, size - 1);
	char svc[2 * PATH_MAX];
	snprintf(svc, sizeof(svc), "auth required " PF_MOD("pam_issue") " issue=%s%s\n",
		 issue, noesc ? " noesc" : "");
	/* pam_issue only prepends to the prompt when PAM_USER is not yet set. */
	pam_handle_t *pamh = pf_start(svc, NULL);
	if (pamh) {
		(void)pam_authenticate(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);
	}
	pf_restore();
	return 0;
}
