.PHONY: test
test: fork_test
	P11NETHSM_CONFIG_FILE=../p11nethsm.conf ./fork_test

fork_test: fork_test.c
	gcc fork_test.c -o fork_test

