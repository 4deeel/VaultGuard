# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iinclude -IC:/msys64/mingw64/include
LDFLAGS = -LC:/msys64/mingw64/lib -lsodium -lssl -lcrypto -lstdc++fs

# Directories
SRCDIR = src
OBJDIR = src
BINDIR = bin
INCDIR = include

# Source files
SOURCES = $(SRCDIR)/main.cpp $(SRCDIR)/vault.cpp $(SRCDIR)/entry.cpp \
          $(SRCDIR)/manager.cpp $(SRCDIR)/encryption.cpp $(SRCDIR)/timer.cpp \
          $(SRCDIR)/logger.cpp $(SRCDIR)/generator.cpp $(SRCDIR)/config.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Executable
TARGET = $(BINDIR)/vaultguard.exe

# Header files
HEADERS = $(INCDIR)/vault.h $(INCDIR)/entry.h $(INCDIR)/manager.h \
          $(INCDIR)/encryption.h $(INCDIR)/timer.h $(INCDIR)/logger.h \
          $(INCDIR)/generator.h $(INCDIR)/config.h

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJECTS)
	@if not exist $(BINDIR) mkdir $(BINDIR)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile source files to object files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Ensure backup.py exists
backup:
	@if not exist backup.py (echo Error: backup.py not found && exit 1)

# Clean up
clean:
	del /Q $(OBJDIR)\*.o $(TARGET)

# Phony targets
.PHONY: all clean backup