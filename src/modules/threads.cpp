#include <algorithm>
#include <atomic>
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

// ═══════════════════════════════════════════════
//   THREAD POOL
// ═══════════════════════════════════════════════
class ThreadPool {
public:
    explicit ThreadPool(int n) : stop(false), completed(0) {
        for (int i = 0; i < n; i++) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] {
                            return stop || !tasks.empty();
                        });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            tasks.push(std::move(task));
        }
        condition.notify_one();
    }

    void wait_all(int total_tasks) {
        std::unique_lock<std::mutex> lock(done_mutex);
        done_cv.wait(lock, [this, total_tasks] {
            return completed.load() >= total_tasks;
        });
    }

    void increment_done() {
        completed.fetch_add(1);
        // notify_one is correct here: wait_all() is the only waiter on done_cv.
        done_cv.notify_one();
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
    std::vector<std::thread>            workers;
    std::queue<std::function<void()>>   tasks;
    std::mutex                          queue_mutex;
    std::condition_variable             condition;
    std::mutex                          done_mutex;
    std::condition_variable             done_cv;
    bool                                stop;
    std::atomic<int>                    completed;
};

// ═══════════════════════════════════════════════

// FIX: параметры ip_ и threads_ вместо target_ip / num_threads (shadow warning)
ThreadScanner::ThreadScanner(const std::string& ip_, int threads_)
    : target_ip(ip_), num_threads(threads_) {}

// ── Проверка одного порта ─────────────────────
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
    tv.tv_sec  = 1;      // 1 секунда для удалённых хостов
    tv.tv_usec = 0;

    bool is_open = false;
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int       error = 0;
        socklen_t len   = sizeof(error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
        is_open = (error == 0);
    }

    close(sock);
    return is_open;
}

// ── Сканирование диапазона портов (один поток) ─
void ThreadScanner::scan_range(int start, int end,
                                std::vector<PortResult>& results) {
    ServiceDetector detector;
    for (int port = start; port <= end; port++) {
        if (check_port(target_ip, port)) {
            PortResult result;
            result.port    = port;
            result.is_open = true;

            result.service = detector.detect(target_ip, port);

            {
                std::lock_guard<std::mutex> lock(results_mutex);
                results.push_back(result);
            }

            std::cout << "\r" << Color::OK
                      << "Порт " << Color::BOLD << result.port
                      << Color::RESET << Color::GREEN << " ОТКРЫТ"
                      << Color::RESET << " | " << Color::YELLOW
                      << result.service << Color::RESET
                      << std::string(20, ' ') << "\n";
        }
    }
}

// ── Главная функция скана ─────────────────────
std::vector<PortResult> ThreadScanner::scan(int start_port, int end_port) {
    std::vector<PortResult> results;

    int total = end_port - start_port + 1;
    // Защита: потоков не больше чем портов
    int threads = std::min(num_threads, total);
    int chunk   = total / threads;

    std::cout << Color::INFO << "Thread Pool: " << Color::CYAN
              << threads << " потоков" << Color::RESET
              << " | Портов: " << total << "\n";

    auto start_time = std::chrono::steady_clock::now();

    ThreadPool pool(threads);

    for (int i = 0; i < threads; i++) {
        int s = start_port + (i * chunk);
        int e = (i == threads - 1) ? end_port : s + chunk - 1;

        pool.enqueue([this, s, e, &results, &pool] {
            scan_range(s, e, results);
            pool.increment_done();
        });
    }

    pool.wait_all(threads);

    // Сортируем по номеру порта
    std::sort(results.begin(), results.end(),
        [](const PortResult& a, const PortResult& b) {
            return a.port < b.port;
        });

    auto end_time = std::chrono::steady_clock::now();
    int  total_sec = std::chrono::duration_cast<std::chrono::seconds>
                     (end_time - start_time).count();

    std::cout << Color::INFO << "Завершено за "
              << Color::YELLOW << total_sec << " сек"
              << Color::RESET
              << " | Открытых портов: " << Color::GREEN
              << results.size() << Color::RESET << "\n";

    return results;
}