TARGET = bin/binary
SRC    = $(wildcard src/*.c) $(wildcard src/ciphers/*.c)
OBJ    = $(patsubst src/%.c, obj/%.o, $(SRC))

run: clean build

clean:
	rm -rf obj bin

build: $(OBJ)
	mkdir -p bin
	gcc -o $(TARGET) $^

obj/%.o: src/%.c
	mkdir -p $(dir $@)
	gcc -c $< -o $@ -Iinclude