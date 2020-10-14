UCX_CONFIG!=pkg-config --cflags --libs --static ucx

all: itme replies wires

itme: itme.c
	gcc -g -O0 -Wall -pedantic -std=c11 -Werror -D_POSIX_C_SOURCE=200809L \
	    $(UCX_CONFIG) -o itme itme.c

wires: wires.c rxpool.c util.c wiring.c
	gcc -fsanitize=address -fsanitize=pointer-compare \
	    -fsanitize=pointer-subtract -g -O0 -Wall -pedantic -std=c11 \
	    -Werror -D_POSIX_C_SOURCE=200809L $(UCX_CONFIG) \
	    -o wires wires.c rxpool.c util.c wiring.c

replies: replies.c rxpool.c util.c
	gcc -fsanitize=address -fsanitize=pointer-compare \
	    -fsanitize=pointer-subtract -g -O0 -Wall -pedantic -std=c11 \
	    -Werror -D_POSIX_C_SOURCE=200809L $(UCX_CONFIG) \
	    -o replies replies.c rxpool.c util.c wiring.c

clean:
	rm -f itme replies wires
