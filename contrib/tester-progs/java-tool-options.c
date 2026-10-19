// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	const char *options = getenv("JAVA_TOOL_OPTIONS");
	printf("%s\n", options ? options : "(unset)");
	return 0;
}
