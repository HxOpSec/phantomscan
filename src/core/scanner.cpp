#include "utils/colors.h"
#include "core/scanner.h"
#include "modules/service_detect.h"
#include <deque>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <chrono>

// FIX: переименовали параметр ip_ чтобы не совпадал с членом класса target_ip
Scanner::Scanner(const std::string& ip_)
    : target_ip(ip_) {}

bool Scanner::check_port(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(target_ip.c_str());

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 300000; // 0.3 секунды

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

std::vector<PortResult> Scanner::scan(int start_port, int end_port) {
    std::vector<PortResult> results;
    std::unordered_map<int, std::string> service_cache;
    std::mutex cache_mutex;
    auto start_time = std::chrono::steady_clock::now();
    int  total      = end_port - start_port + 1;

    const unsigned int concurrency =
        std::max(4u, std::thread::hardware_concurrency());
    const int batch_size = static_cast<int>(concurrency * 4);

    struct Task {
        int port;
        std::future<std::optional<PortResult>> fut;
    };
    std::deque<Task> tasks;

    auto launch_task = [&](int port) {
        tasks.push_back(Task{
            port,
            std::async(std::launch::async, [this, port, &service_cache, &cache_mutex]() {
                auto split_service_version = [](const std::string& detected,
                                                std::string& service_out,
                                                std::string& version_out) {
                    service_out = detected;
                    version_out.clear();
                    size_t sp = detected.find(' ');
                    if (sp != std::string::npos) {
                        service_out = detected.substr(0, sp);
                        if (sp + 1 < detected.size())
                            version_out = detected.substr(sp + 1);
                    }
                };
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    auto cached = service_cache.find(port);
                    if (cached != service_cache.end()) {
                        PortResult cached_result;
                        cached_result.port    = port;
                        cached_result.is_open = true;
                        split_service_version(cached->second, cached_result.service, cached_result.version);
                        return std::optional<PortResult>(cached_result);
                    }
                }

                if (!check_port(port)) return std::optional<PortResult>{};
                PortResult result;
                result.port    = port;
                result.is_open = true;
                ServiceDetector detector;
                std::string detected = detector.detect(target_ip, port);
                split_service_version(detected, result.service, result.version);
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    service_cache.emplace(port, detected);
                }
                return std::optional<PortResult>(result);
            })
        });
    };

    auto process_task = [&](Task& task, int processed_count) {
        auto res = task.fut.get();
        if (processed_count % 50 == 0) {
            int done    = processed_count;
            int percent = (done * 100) / total;
            auto now    = std::chrono::steady_clock::now();
            int elapsed = std::chrono::duration_cast<std::chrono::seconds>
                          (now - start_time).count();

            int         bar_width = 30;
            int         filled    = (percent * bar_width) / 100;
            std::string bar       = "[";
            for (int i = 0; i < bar_width; i++)
                bar += (i < filled) ? "█" : "░";
            bar += "]";

            std::cout << "\r" << Color::MAGENTA
                      << bar << " " << percent << "% | "
                      << "Порт: " << task.port << "/" << end_port << " | "
                      << elapsed << "с"
                      << Color::RESET << std::flush;
        }

        if (res) {
            results.push_back(*res);

            std::cout << "\r" << Color::OK
                      << "Порт " << Color::BOLD << res->port << Color::RESET
                      << Color::GREEN << " ОТКРЫТ" << Color::RESET
                      << " | " << Color::YELLOW << res->service << Color::RESET
                      << std::string(20, ' ') << "\n";
        }
    };

    int processed_count = 0;
    for (int port = start_port; port <= end_port; port++) {
        launch_task(port);

        if (static_cast<int>(tasks.size()) >= batch_size) {
            Task task = std::move(tasks.front());
            tasks.pop_front();
            processed_count++;
            process_task(task, processed_count);
        }
    }

    while (!tasks.empty()) {
        Task task = std::move(tasks.front());
        tasks.pop_front();
        processed_count++;
        process_task(task, processed_count);
    }

    auto end_time  = std::chrono::steady_clock::now();
    int  total_sec = std::chrono::duration_cast<std::chrono::seconds>
                     (end_time - start_time).count();
    std::cout << "\n" << Color::INFO
              << "Сканирование завершено за "
              << Color::YELLOW << total_sec << " секунд"
              << Color::RESET << "\n";

    std::sort(results.begin(), results.end(),
        [](const PortResult& a, const PortResult& b) {
            return a.port < b.port;
        });

    return results;
}
