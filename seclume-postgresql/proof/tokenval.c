/*
 * A PostgreSQL 18 OAuth validator for the proof and nothing else: a token is
 * valid when it is the one in /shared/token, and it then stands for the role
 * that asked. A real validator checks a signed JWT against the issuer's keys.
 */
#include "postgres.h"
#include "fmgr.h"
#include "libpq/oauth.h"

#include <stdio.h>
#include <string.h>

PG_MODULE_MAGIC;

static bool
validate_token(const ValidatorModuleState *state, const char *token,
			   const char *role, ValidatorModuleResult *result)
{
	char		expected[512];
	size_t		length = 0;
	FILE	   *file = fopen("/shared/token", "r");

	if (file != NULL)
	{
		length = fread(expected, 1, sizeof(expected) - 1, file);
		fclose(file);
	}
	expected[length] = '\0';
	result->authorized = length > 0 && strcmp(token, expected) == 0;
	result->authn_id = result->authorized ? pstrdup(role) : NULL;
	return true;
}

static const OAuthValidatorCallbacks callbacks = {
	PG_OAUTH_VALIDATOR_MAGIC,
	.validate_cb = validate_token,
};

const OAuthValidatorCallbacks *
_PG_oauth_validator_module_init(void)
{
	return &callbacks;
}
