
#include "log.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstring> // for strrchr

namespace logging {

    static std::ofstream log_file_stream;
    static bool log_file_enabled = false;

    void init_log_to_file(const std::string& filename) {
        log_file_stream.open(filename, std::ios::out | std::ios::trunc);
        if (log_file_stream.is_open()) {
            log_file_enabled = true;
        } else {
            std::cerr << "⚠️ Failed to open log file: " << filename << std::endl;
        }
    }

    void close_log_file() {
        if (log_file_stream.is_open()) {
            log_file_stream.close();
            log_file_enabled = false;
        }
    }

    LogMessage::LogMessage(const char* file, int line, const char* function) {
        using namespace std::chrono;
        auto now       = system_clock::now();
        auto now_time  = system_clock::to_time_t(now);
        auto us        = duration_cast<microseconds>(now.time_since_epoch()) % 1000000;
        std::tm local_tm;
#ifdef _WIN32
        localtime_s(&local_tm, &now_time);
#else
        localtime_r(&now_time, &local_tm);
#endif

        // 格式化时间：HH:MM:SS.micro
        char time_buf[32];
        std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &local_tm);

        // 取文件名
        const char* filename_only = std::strrchr(file, '/');
        if (!filename_only) filename_only = std::strrchr(file, '\\');
        if (!filename_only) filename_only = file;
        else filename_only++; // skip '/'

        // 拼装日志头
        stream_ << "[" << time_buf << "." << std::setw(6) << std::setfill('0') << us.count()
                << "][" << filename_only
                << "][" << function << "(" << line << ")]"
                << "[INFO] ";
    }

    LogMessage::~LogMessage() {
        stream_ << "\n";
        const std::string& output = stream_.str();
        std::cerr << output;
        if (log_file_enabled && log_file_stream.is_open()) {
            log_file_stream << output;
            log_file_stream.flush();
        }
    }

    std::ostream& LogMessage::stream() {
        return stream_;
    }

} // namespace logging
