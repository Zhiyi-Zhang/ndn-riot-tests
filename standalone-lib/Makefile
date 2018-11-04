CC = arm-none-eabi-gcc

main:
	$(CC) --specs=nosys.specs -static -L. -l ndn-standalone.a -I../../ndn-riot main.c -o main
