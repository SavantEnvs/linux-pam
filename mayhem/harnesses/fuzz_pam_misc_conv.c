/*
 * libpam_misc misc_conv(): the text conversation function behind su, login and
 * passwd. It prints each prompt and reads the user's responses from stdin with
 * read_string (one line per prompt, INPUTSIZE limit, EOF / no-newline handling),
 * then builds the pam_response array, or unwinds it on a failed conversation.
 * Input: <count> <style bytes...> <prompt> NUL ... <prompt> NUL <stdin bytes>.
 *   count = 1 + byte % PAM_MAX_NUM_MSG messages; each style byte selects
 *   PAM_PROMPT_ECHO_OFF / PAM_PROMPT_ECHO_ON / PAM_ERROR_MSG / PAM_TEXT_INFO or an
 *   unknown style; the rest of the input is what the user types on fd 0.
 * PAM_BINARY_PROMPT is not generated: no binary handler is installed (the default),
 * so misc_conv fails it before reading the message, and a binary message is a
 * length-prefixed buffer built by a module, not text a user controls.
 * stdin is a file (not a tty), as when su/passwd read from a pipe.
 */
#include "pam_fuzz_common.h"
#include <security/pam_misc.h>

static const int styles[] = { PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON,
			      PAM_ERROR_MSG, PAM_TEXT_INFO, 0x7f };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pf_init();
	if (size < 1)
		return -1;
	int num = 1 + data[0] % PAM_MAX_NUM_MSG;
	if (size < 1 + (size_t)num)
		return -1;
	struct pam_message msgs[PAM_MAX_NUM_MSG];
	const struct pam_message *pmsgs[PAM_MAX_NUM_MSG];
	char *texts[PAM_MAX_NUM_MSG];
	const uint8_t *p = data + 1 + num, *f;
	size_t left = size - 1 - num, n;
	for (int i = 0; i < num; i++) {
		f = pf_field(&p, &left, &n);
		texts[i] = pf_strndup(f, n);
		msgs[i].msg_style = styles[data[1 + i] % (sizeof(styles) / sizeof(styles[0]))];
		msgs[i].msg = texts[i];
		pmsgs[i] = &msgs[i];
	}
	/* Remaining bytes are the terminal input, delivered on fd 0 from a file. */
	const char *in = pf_write("stdin", p, left);
	int infd = open(in, O_RDONLY);
	if (infd < 0)
		pf_die(in);
	int saved = dup(STDIN_FILENO);
	if (dup2(infd, STDIN_FILENO) < 0)
		pf_die("dup2");
	close(infd);

	struct pam_response *resp = NULL;
	if (misc_conv(num, pmsgs, &resp, NULL) == PAM_SUCCESS && resp) {
		for (int i = 0; i < num; i++) {
			free(resp[i].resp);
		}
		free(resp);
	}

	if (saved >= 0) {
		dup2(saved, STDIN_FILENO);
		close(saved);
	} else {
		close(STDIN_FILENO);
	}
	for (int i = 0; i < num; i++)
		free(texts[i]);
	pf_restore();
	return 0;
}
