CXXFLAGS = -Wall -std=c++17 -Dgpu_float_type=cl_double -g
LDFLAGS = -L/usr/local/lib -lpthread -larchive -lplist-2.0 -lgeneral

LDFLAGS+= -lOpenCL
#LDFLAGS+= -framework OpenCL

CXX := clang++

OBJ = UIDOGPUManager.o UIDO.o UIDOGPU.o main.o keyschedule.o bs.o aes128.o bsdcrypto/rijndael.o bsdcrypto/sha1.o bsdcrypto/key_wrap.o bsdcrypto/pbkdf2.o

all: uido

uido: $(OBJ)
	$(CXX) $(CXXFLAGS) -o uido $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -rf $(OBJ) uido
