#!/bin/bash

# ============================================
#   PhantomScan v1.0 — Установщик
#   Автор: Umedjon
#   Платформа: Linux (Parrot OS / Kali / Ubuntu)
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${CYAN}"
echo "██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗"
echo "██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║"
echo "██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║"
echo "██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║"
echo "██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║"
echo "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"
echo -e "${RESET}"
echo -e "${CYAN}  PhantomScan v1.0 Installer  |  by Umedjon${RESET}"
echo -e "${CYAN}──────────────────────────────────────────${RESET}"
echo ""

# Проверяем root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Запусти с sudo: sudo ./install.sh${RESET}"
    exit 1
fi

# Определяем дистрибутив
if [ -f /etc/debian_version ]; then
    PKG="apt"
elif [ -f /etc/arch-release ]; then
    PKG="pacman"
else
    echo -e "${YELLOW}[!] Неизвестный дистрибутив — устанавливай вручную${RESET}"
    exit 1
fi

echo -e "${CYAN}[*] Обновляем пакеты...${RESET}"
if [ "$PKG" = "apt" ]; then
    apt update -q
elif [ "$PKG" = "pacman" ]; then
    pacman -Sy
fi

echo -e "${CYAN}[*] Устанавливаем зависимости...${RESET}"

DEPS=("g++" "libpcap-dev" "nmap" "curl" "openssl" "make")

for dep in "${DEPS[@]}"; do
    echo -ne "${CYAN}    → ${dep}... ${RESET}"
    if [ "$PKG" = "apt" ]; then
        apt install -y "$dep" -q > /dev/null 2>&1
    elif [ "$PKG" = "pacman" ]; then
        pacman -S --noconfirm "$dep" > /dev/null 2>&1
    fi
    echo -e "${GREEN}OK${RESET}"
done

# Создаём нужные папки
echo -e "${CYAN}[*] Создаём папки...${RESET}"
mkdir -p builds reports

# Компилируем
echo -e "${CYAN}[*] Компилируем PhantomScan...${RESET}"
make rebuild

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}[+] Установка завершена успешно!${RESET}"
    echo ""
    echo -e "${CYAN}  Запуск:${RESET}"
    echo -e "${GREEN}  sudo ./builds/phantomscan${RESET}"
    echo ""
else
    echo -e "${RED}[!] Ошибка компиляции! Проверь зависимости.${RESET}"
    exit 1
fi