OBJ = main.o CRC32.o
CXXFLAGS = --std=c++11
client:$(OBJ)
	g++ -o  $@ $^ -lpthread
.PHONY:clean
clean: 
	rm -rf $(OBJ)
