TARGET = bin/binary
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))

run: clean build

clean:
	rm -rf obj
	rm -rf bin

build: $(OBJ)
	mkdir -p bin
	gcc -o $(TARGET) $^

obj/%.o: src/%.c
	mkdir -p obj
	gcc -c $< -o $@ -Iinclude