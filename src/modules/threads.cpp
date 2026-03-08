#include <algorithm>
#include <chrono>
#include "modules/threads.h"
#include "modules/service_detect.h"
#include "utils/colors.h"
#include <iostream>
#include <thread>
#include <queue>
#include <functional>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

// =============================================
//   THREAD POOL — пул потоков
// =============================================
class ThreadPool {
public:
    ThreadPool(int num_threads) : stop(false) {
        for (int i = 0; i < num_threads; i++) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        // Ждём задачу или сигнал остановки
                        condition.wait(lock, [this] {
                            return stop || !tasks.empty();
                        });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task(); // Выполняем задачу
                }
            });
        }
    }

    // Добавляем задачу в очередь
    void enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            tasks.push(std::move(task));
        }
        condition.notify_one(); // Будим один поток
    }

    // Ждём завершения всех задач
    void wait_all(int total_tasks) {
        std::unique_lock<std::mutex> lock(done_mutex);
        done_cv.wait(lock, [this, total_tasks] {
            return completed >= total_tasks;
        });
    }

    void increment_done() {
        {
            std::lock_guard<std::mutex> lock(done_mutex);
            completed++;
        }
        done_cv.notify_all();
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (auto& w : workers) w.join();
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::mutex done_mutex;
    std::condition_variable done_cv;
    int completed = 0;
    bool stop;
};

// =============================================

ThreadScanner::ThreadScanner(const std::string& target_ip, int num_threads)
    : target_ip(target_ip), num_threads(num_threads) {}

static bool check_port(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 300000; // 300мс

    bool is_open = false;
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
        is_open = (error == 0);
    }

    close(sock);
    return is_open;
}

void ThreadScanner::scan_range(int start, int end,
                                std::vector<PortResult>& results) {
    for (int port = start; port <= end; port++) {
        if (check_port(target_ip, port)) {
            PortResult result;
            result.port    = port;
            result.is_open = true;

            ServiceDetector detector;
            result.service = detector.detect(target_ip, port);

            std::lock_guard<std::mutex> lock(results_mutex);
            results.push_back(result);

            std::cout << "\r" << Color::OK
                      << "Порт " << Color::BOLD << result.port
                      << Color::RESET << Color::GREEN << " ОТКРЫТ"
                      << Color::RESET << " | " << Color::YELLOW
                      << result.service << Color::RESET
                      << std::string(20, ' ') << std::endl;
        }
    }
}

std::vector<PortResult> ThreadScanner::scan(int start_port, int end_port) {
    std::vector<PortResult> results;

    int total = end_port - start_port + 1;
    int chunk = total / num_threads;

    std::cout << Color::INFO << "Thread Pool: " << Color::CYAN
              << num_threads << " потоков" << Color::RESET << std::endl;

    auto start_time = std::chrono::steady_clock::now();

    // Создаём пул — потоки живут всё время скана
    ThreadPool pool(num_threads);

    // Раздаём задачи — каждый поток получает свой диапазон
    for (int i = 0; i < num_threads; i++) {
        int start = start_port + (i * chunk);
        int end   = (i == num_threads - 1) ? end_port : start + chunk - 1;

        pool.enqueue([this, start, end, &results, &pool] {
            scan_range(start, end, results);
            pool.increment_done();
        });
    }

    // Ждём все задачи
    pool.wait_all(num_threads);

    // Сортируем по номеру порта
    std::sort(results.begin(), results.end(),
        [](const PortResult& a, const PortResult& b) {
            return a.port < b.port;
        });

    auto end_time = std::chrono::steady_clock::now();
    int total_sec = std::chrono::duration_cast<std::chrono::seconds>(
        end_time - start_time).count();

    std::cout << Color::INFO << "Завершено за "
              << Color::YELLOW << total_sec << " сек"
              << Color::RESET << std::endl;

    return results;
}