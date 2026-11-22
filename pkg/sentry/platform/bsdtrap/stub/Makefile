# bsdtrap stub: freestanding, static, linked above the app address range and
# branded for gsb.ko (GSB note + EI_OSABI 255). Build on FreeBSD:
#   make            -> gsb-bsdtrap-stub
CC?=		cc
CFLAGS=		-O2 -g -Wall -Werror -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-pic -fno-pie -fcf-protection=none \
		-mgeneral-regs-only -mcmodel=large
LDFLAGS=	-static -nostdlib -Wl,-no-pie -Wl,--build-id=none \
		-Wl,--image-base=0x7f0000000000

all: gsb-bsdtrap-stub

gsb-bsdtrap-stub: stub.c stub_rt.S bsdtrap_abi.h
	${CC} ${CFLAGS} ${LDFLAGS} -o ${.TARGET}.tmp ${.ALLSRC:M*.[cS]}
	brandelf -f 255 ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

clean:
	rm -f gsb-bsdtrap-stub gsb-bsdtrap-stub.tmp
