steam-signature-fix32.so: steam_signature_fix.c steam_signature_forward.h
	gcc -m32 -std=gnu11 -O2 -g -fPIC -shared \
	    -Wall -Wextra -Werror -Wl,-z,relro,-z,now \
	    steam_signature_fix.c -ldl -pthread \
	    -o steam-signature-fix32.so
