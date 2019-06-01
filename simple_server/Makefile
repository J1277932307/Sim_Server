VPATH = ./ ./configurer ./log ./process ./util ./signal ./socket ./memory ./crc ./thread
CXXFLAGS= --std=c++11 

OBJ= main.o Configurer.o Logger.o utils.o Signal.o Process.o  Memory.o Socket.o LogicSocket.o  CRC32.o Thread.o


sim_server:$(OBJ)
	g++ -o $@ $^ -lpthread
.PHONY:clean
clean:
	rm -rf $(OBJ)


