UCX_CONFIG!=pkg-config --cflags --libs --static ucx

all: itme wires

itme: itme.c util.c
	gcc -g -O0 -Wall -pedantic -std=c11 -Werror -D_POSIX_C_SOURCE=200809L \
	    $(UCX_CONFIG) -o itme itme.c util.c

INCS= bits.h rxpool.h tag.h util.h wireup.h wiring.h wiring_impl.h

wires: wires.c rxpool.c util.c wiring.c $(INCS)
	gcc -fsanitize=address -fsanitize=pointer-compare \
	    -fsanitize=pointer-subtract -g -O0 -Wall -pedantic -std=c11 \
	    -Werror -D_POSIX_C_SOURCE=200809L $(UCX_CONFIG) \
	    -o wires wires.c rxpool.c util.c wiring.c

clean:
	rm -f itme wires
