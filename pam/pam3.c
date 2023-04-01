#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <security/pam_appl.h>

#define MY_PAM_SERVICE "login"
#define USER "myuser"
#define PASSWORD "mypassowrd"

static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr) {
    char *pass = malloc(strlen(appdata_ptr) + 1);
    strcpy(pass, appdata_ptr);

    int i;

    *resp = calloc(num_msg, sizeof(struct pam_response));

    for (i = 0; i < num_msg; ++i) {
        /* Ignore all PAM messages except prompting for hidden input */
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
            continue;

        /* Assume PAM is only prompting for the password as hidden input */
        resp[i]->resp = pass;
    }

    return PAM_SUCCESS;
}

int main()
{
	struct pam_conv conv = {&pam_conversation, (void *) PASSWORD};
	pam_handle_t *handle;
	int startResult, authResult;
	startResult = pam_start(MY_PAM_SERVICE, NULL, &conv, &handle); 
	if (startResult != PAM_SUCCESS) {
		printf("Start -- %s (%d)\n",pam_strerror(handle,startResult),startResult);
		return 1;
	}
    	authResult = pam_authenticate(handle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
	if (authResult != PAM_SUCCESS) {
		printf("AUTH -- %s (%d)\n",pam_strerror(handle,authResult),authResult);
		return 1;
	}

    	pam_end(handle, authResult);
	printf("AUTH -- %s (%d)\n",pam_strerror(handle,authResult),authResult);

	return 0;
}
