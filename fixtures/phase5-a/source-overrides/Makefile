all: out/rom.bin
out:
	/bin/mkdir -p out
src/boot/sega.s: /sgdk/src/boot/sega.s
	/bin/cp /sgdk/src/boot/sega.s src/boot/sega.s
out/main.o: src/main.c out
	/usr/bin/m68k-elf-gcc -DSGDK_GCC -m68000 -Wall -Wextra -Wno-shift-negative-value -Wno-main -Wno-unused-parameter -fno-builtin -ffunction-sections -fdata-sections -fms-extensions -I. -Iinc -Isrc -Ires -I/sgdk/inc -I/sgdk/res -B/sgdk/bin -O2 -fno-lto -c src/main.c -o out/main.o
out/rom_head.o: src/boot/rom_head.c out
	/usr/bin/m68k-elf-gcc -DSGDK_GCC -m68000 -Wall -Wextra -Wno-shift-negative-value -Wno-main -Wno-unused-parameter -fno-builtin -ffunction-sections -fdata-sections -fms-extensions -I. -Iinc -Isrc -Ires -I/sgdk/inc -I/sgdk/res -B/sgdk/bin -O2 -fno-lto -c src/boot/rom_head.c -o out/rom_head.o
out/rom_head.bin: out/rom_head.o
	/usr/bin/m68k-elf-objcopy -O binary out/rom_head.o out/rom_head.bin
out/sega.o: src/boot/sega.s out/rom_head.bin
	/usr/bin/m68k-elf-gcc -x assembler-with-cpp -Wa,--register-prefix-optional,--bitwise-or -DSGDK_GCC -m68000 -Wall -Wextra -Wno-shift-negative-value -Wno-main -Wno-unused-parameter -fno-builtin -ffunction-sections -fdata-sections -fms-extensions -I. -Iinc -Isrc -Ires -I/sgdk/inc -I/sgdk/res -B/sgdk/bin -O2 -fno-lto -c src/boot/sega.s -o out/sega.o
out/rom.out: out/main.o out/sega.o
	/usr/bin/m68k-elf-gcc -m68000 -B/sgdk/bin -n -T /sgdk/md.ld -nostdlib out/sega.o out/main.o /sgdk/lib/libmd.a -lgcc -o out/rom.out -Wl,--gc-sections -Wl,-Map,out/link.map -fno-lto
out/rom.bin: out/rom.out
	/usr/bin/m68k-elf-objcopy -O binary out/rom.out out/rom.bin
	/opt/jre-minimal/bin/java -Xint -XX:+UseSerialGC -XX:ActiveProcessorCount=1 -XX:+DisableAttachMechanism -XX:-UsePerfData -jar /sgdk/bin/sizebnd.jar out/rom.bin -sizealign 131072 -checksum
