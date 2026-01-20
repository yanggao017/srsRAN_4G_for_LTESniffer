#ifndef LOG_H
#define LOG_H

#include <sstream>
#include <string>
#include <ostream>

namespace logging {

    class LogMessage {
    public:
        LogMessage(const char* file, int line, const char* function);
        ~LogMessage();
        std::ostream& stream();

    private:
        std::ostringstream stream_;
    };

    void init_log_to_file(const std::string& filename = "log.txt");
    void close_log_file();

} // namespace logging

#define MY_LOG() logging::LogMessage(__FILE__, __LINE__, __FUNCTION__).stream()

#endif // LOG_H
