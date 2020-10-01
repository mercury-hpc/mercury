UCX_CONFIG!=pkg-config --cflags --libs --static ucx

all: replies itme

itme: itme.c
	gcc -g -O0 -Wall -pedantic -std=c11 -Werror -D_POSIX_C_SOURCE=200809L \
	    $(UCX_CONFIG) -o itme itme.c

replies: replies.c
	gcc -g -O0 -Wall -pedantic -std=c11 -Werror -D_POSIX_C_SOURCE=200809L \
	    $(UCX_CONFIG) -o replies replies.c
