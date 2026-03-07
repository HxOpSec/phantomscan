#include "modules/menu.h"
#include "utils/banner.h"

int main(int argc, char* argv[]) {
    // Если передан аргумент — быстрый режим
    if (argc >= 2) {
        // Запускаем старый режим через меню
        Menu menu;
        menu.run();
        return 0;
    }

    // Без аргументов — интерактивное меню
    Menu menu;
    menu.run();
    return 0;
}