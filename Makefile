CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I./include
LDFLAGS  = -lpcap -lpthread
TARGET   = builds/phantomscan
SRC      = $(shell find src -name "*.cpp")
OBJ      = $(SRC:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	find src -name "*.o" -delete
	rm -f $(TARGET)

rebuild: clean all

.PHONY: all clean rebuild
