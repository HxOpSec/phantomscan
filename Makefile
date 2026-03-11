# ╔══════════════════════════════════════════╗
# ║        PhantomScan  —  Makefile          ║
# ╚══════════════════════════════════════════╝

CXX      = g++
# FIX: добавили -O2 (оптимизация), -Wshadow (предупреждение о shadowing),
#      убрали -Wno-ignored-attributes (он скрывал реальные баги)
CXXFLAGS = -std=c++17 -Wall -Wextra -Wshadow -O2 -I./include

# FIX: добавили -lresolv — нужен для резолвинга DNS на некоторых системах
LDFLAGS  = -lpcap -lpthread -lresolv

TARGET   = builds/phantomscan
SRC      = $(shell find src -name "*.cpp")
OBJ      = $(SRC:.cpp=.o)

# Цвета для вывода
GREEN  = \033[32m
YELLOW = \033[33m
CYAN   = \033[36m
RESET  = \033[0m

# ── Основная цель ────────────────────────────────────────
all: builds_dir $(TARGET)
	@echo "$(GREEN)[+] Сборка завершена: $(TARGET)$(RESET)"
	@echo "$(CYAN)[i] Запуск: sudo ./$(TARGET)$(RESET)"

# FIX: автоматически создаём папку builds/ перед сборкой
# Раньше make падал с ошибкой если папки не было
builds_dir:
	@mkdir -p builds

$(TARGET): $(OBJ)
	@echo "$(YELLOW)[*] Линковка...$(RESET)"
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.cpp
	@echo "$(CYAN)[>] Компиляция: $<$(RESET)"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ── Очистка ──────────────────────────────────────────────
clean:
	@echo "$(YELLOW)[*] Очистка .o файлов...$(RESET)"
	@find src -name "*.o" -delete
	@rm -f $(TARGET)
	@echo "$(GREEN)[+] Очищено$(RESET)"

# ── Полная пересборка ────────────────────────────────────
rebuild: clean all

# FIX: добавили install цель — копирует бинарник в /usr/local/bin
install: all
	@echo "$(YELLOW)[*] Установка в /usr/local/bin/phantomscan$(RESET)"
	@sudo cp $(TARGET) /usr/local/bin/phantomscan
	@sudo chmod 755 /usr/local/bin/phantomscan
	@echo "$(GREEN)[+] Установлено. Теперь можно запускать: sudo phantomscan$(RESET)"

# FIX: добавили uninstall
uninstall:
	@sudo rm -f /usr/local/bin/phantomscan
	@echo "$(GREEN)[+] Удалено$(RESET)"

# FIX: добавили info — показывает статистику проекта
info:
	@echo "$(CYAN)Файлов .cpp : $(shell find src -name '*.cpp' | wc -l)$(RESET)"
	@echo "$(CYAN)Файлов .h   : $(shell find include -name '*.h' | wc -l)$(RESET)"
	@echo "$(CYAN)Строк кода  : $(shell find src -name '*.cpp' | xargs wc -l | tail -1 | awk '{print $$1}')$(RESET)"
	@if [ -f $(TARGET) ]; then \
		echo "$(CYAN)Размер бин. : $(shell du -sh $(TARGET) | cut -f1)$(RESET)"; \
	fi

.PHONY: all clean rebuild install uninstall info builds_dir