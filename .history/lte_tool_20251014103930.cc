// lte_tool.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <sstream>
#include <map>
#include "srsran/json.hpp"
using json = nlohmann::json;
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
// ==================== 工具函数 ====================
/*
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}*/
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        std::cout << buffer.data();      // 👈 实时输出到屏幕
        std::cout.flush();               // 立即刷新
        result += buffer.data();         // 同时保存用于解析
    }
    return result;
}

bool file_exists(const std::string& path) {
    return fs::exists(path);
}

void create_dir(const std::string& path) {
    if (!fs::exists(path)) {
        fs::create_directories(path);
    }
}
void copy_if_exists(const std::string& src, const std::string& dst) {
    if (file_exists(src)) {
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
    }
}
json read_json(const std::string& path) {
    std::ifstream f(path);
    json j;
    f >> j;
    return j;
}

void write_json(const std::string& path, const json& j) {
    std::ofstream f(path);
    f << j.dump(2) << std::endl;
}
// 辅助函数：清除 output 目录
void clear_output_dir() {
    std::vector<std::string> files = {
        "../output/mib.hex",
        "../output/sib1.hex",
        "../output/sib2.hex",
        "../output/mib.json",
        "../output/sib1.json",
        "../output/sib2.json"
    };
    for (const auto& file : files) {
        if (file_exists(file)) {
            std::remove(file.c_str());
        }
    }
}
// ==================== scan 子命令 ====================

int handle_scan(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: lte_tool scan --band <band> [--force]\n";
        return 1;
    }

    int band = -1;
    bool force = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--band" && i + 1 < argc) {
            band = std::stoi(argv[++i]);
        } else if (arg == "--force") {
            force = true;
        }
    }

    if (band == -1) {
        std::cerr << "Error: --band is required\n";
        return 1;
    }

    std::string cache_dir = "cache/band_" + std::to_string(band);
    std::string cells_json = cache_dir + "/cells.json";

    // 1. 检查是否已有缓存
    if (file_exists(cells_json) && !force) {
        std::cout << "✅ Using cached scan result for band " << band << "\n";
        json cells = read_json(cells_json);
        std::cout << cells.dump(2) << std::endl;
        return 0;
    }

    // 2. 清除旧缓存（如果 force）
    if (force && file_exists(cache_dir)) {
        fs::remove_all(cache_dir);
    }
    create_dir(cache_dir);

    // 3. 执行 cell_search
    std::cout << "🔍 Scanning band " << band << "...\n";
    std::string cmd = "./lib/examples/cell_search -b " + std::to_string(band) + " -a type=x300,time_source=gpsdo -s 94 -e 104";
    std::string output = exec(cmd.c_str());

    // 4. 解析 cell_search 输出：只处理最终总结行（"Found CELL <freq> MHz, EARFCN=..."）
    std::vector<json> cells;
    std::istringstream iss(output);
    std::string line;

    while (std::getline(iss, line)) {
        // 只处理以 "Found CELL" 开头，且包含 "MHz, EARFCN=" 的行（最终总结）
        if (line.find("Found CELL") == 0 && 
            line.find("MHz, EARFCN=") != std::string::npos) {
            
            // 示例：
            // Found CELL 2120.0 MHz, EARFCN=100, PHYID=420, 100 PRB, 2 ports, PSS power=-61.9 dBm

            double freq_mhz = 0.0;
            int earfcn = 0, pci = 0, nof_prb = 0, nof_ports = 0;

            // 提取频率：格式 "Found CELL XXXX.X MHz"
            size_t freq_pos = line.find("Found CELL ");
            if (freq_pos != std::string::npos) {
                size_t freq_end = line.find(" MHz", freq_pos + 11);
                if (freq_end != std::string::npos) {
                    std::string freq_str = line.substr(freq_pos + 11, freq_end - (freq_pos + 11));
                    freq_mhz = std::stod(freq_str);
                }
            }

            // 提取 EARFCN
            size_t earfcn_pos = line.find("EARFCN=");
            if (earfcn_pos != std::string::npos) {
                size_t end = line.find(",", earfcn_pos);
                if (end == std::string::npos) end = line.length();
                earfcn = std::stoi(line.substr(earfcn_pos + 7, end - (earfcn_pos + 7)));
            }

            // 提取 PHYID (即 PCI)
            size_t pci_pos = line.find("PHYID=");
            if (pci_pos != std::string::npos) {
                size_t end = line.find(",", pci_pos);
                if (end == std::string::npos) end = line.length();
                pci = std::stoi(line.substr(pci_pos + 6, end - (pci_pos + 6)));
            }

            // 提取 PRB 数量
            size_t prb_pos = line.find(" PRB");
            if (prb_pos != std::string::npos) {
                size_t start = line.rfind(",", prb_pos);
                if (start == std::string::npos) start = line.rfind(" ", prb_pos);
                if (start != std::string::npos) {
                    std::string prb_str = line.substr(start + 1, prb_pos - (start + 1));
                    prb_str.erase(0, prb_str.find_first_not_of(" "));
                    nof_prb = std::stoi(prb_str);
                }
            }

            // 提取端口数
            size_t ports_pos = line.find("ports");
            if (ports_pos != std::string::npos && line.find("ports,") != std::string::npos) {
                size_t start = line.rfind(",", ports_pos);
                if (start == std::string::npos) start = line.rfind(" ", ports_pos);
                if (start != std::string::npos) {
                    std::string ports_str = line.substr(start + 1, ports_pos - (start + 1));
                    ports_str.erase(0, ports_str.find_first_not_of(" "));
                    nof_ports = std::stoi(ports_str);
                }
            }

            // 构建小区信息
            json cell = {
                {"pci", pci},
                {"freq_mhz", freq_mhz},
                {"earfcn", earfcn},
                {"nof_prb", nof_prb},
                {"nof_ports", nof_ports},
                {"type", "FDD"} // 可选：根据 EARFCN 推断
            };
            cells.push_back(cell);
        }
    }

    if (cells.empty()) {
        std::cerr << "❌ No cells found in band " << band << "\n";
        return 1;
    }

    // 5. 保存 cells.json
    write_json(cells_json, cells);
    std::cout << "💾 Saved " << cells.size() << " cells to " << cells_json << "\n";

    // 6. 对每个小区，运行 pdsch_ue 并通过输出文件判断是否有效
    std::vector<json> valid_cells;

    const double TIMEOUT_SEC = 5;  // 300ms 超时
    const std::string TIMEOUT_CMD = "timeout " + std::to_string(TIMEOUT_SEC) + "s ";

    for (const auto& cell : cells) {
        int pci = cell["pci"];
        double freq_mhz = cell["freq_mhz"];
        std::string cell_dir = cache_dir + "/cell_" + std::to_string(pci);
        create_dir(cell_dir);

        std::string config_json = cell_dir + "/config.json";
        if (file_exists(config_json) && !force) {
            valid_cells.push_back(cell);
            continue;
        }

        std::cout << "📡 Testing cell PCI=" << pci << " at " << freq_mhz << " MHz (timeout: " << TIMEOUT_SEC << "s)...\n";

        // 构造带超时的命令
        std::string pdsch_cmd = TIMEOUT_CMD + "./lib/examples/pdsch_ue -f " + std::to_string(freq_mhz * 1e6) + " -d";

        // 执行命令，不捕获输出（丢弃 stdout/stderr）
        int ret = std::system((pdsch_cmd + " > /dev/null 2>&1").c_str());

        // 检查是否成功生成了 MIB 文件（关键指标）
        bool mib_decoded = file_exists("../output/mib.json");

        if (mib_decoded) {
            std::cout << "✅ Valid cell confirmed: PCI=" << pci << ", MIB decoded successfully\n";

            // 保存所有输出文件
            copy_if_exists("../output/mib.hex",   cell_dir + "/mib.hex");
            copy_if_exists("../output/sib1.hex",  cell_dir + "/sib1.hex");
            copy_if_exists("../output/sib2.hex",  cell_dir + "/sib2.hex");
            copy_if_exists("../output/mib.json",  cell_dir + "/mib.json");
            copy_if_exists("../output/sib1.json", cell_dir + "/sib1.json");
            copy_if_exists("../output/sib2.json", cell_dir + "/sib2.json");

            valid_cells.push_back(cell);
        } else {
            if (ret == 124) {
                std::cerr << "❌ Timeout: No MIB decoded for PCI=" << pci << "\n";
            } else {
                std::cerr << "❌ pdsch_ue failed or exited early (code: " << ret << ") for PCI=" << pci << "\n";
            }
            // 不保存，跳过
        }
    }

    // 更新为有效小区列表
    cells = valid_cells;

    // 最终输出
    std::cout << "✅ Scan completed. Results saved in " << cache_dir << "\n";
    std::cout << json(cells).dump(2) << std::endl;
    return 0;
}

// ==================== gen-sib2 子命令（示例）====================

int handle_gen_sib2(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: lte_tool gen-sib2 --config <config.json> --output sib2.hex\n";
        return 1;
    }

    std::string config_path, output_path;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        }
    }

    if (config_path.empty() || output_path.empty()) {
        std::cerr << "Error: --config and --output are required\n";
        return 1;
    }

    json config = read_json(config_path);

    // 这里调用你的 gen_sib2_acbarring 函数
    // 示例：假设你有一个函数 gen_sib2(uint8_t* buf, uint32_t len, uint32_t* out_len, json config)
    // 然后写入 output_path

    std::cout << "📄 Generated SIB2 message from " << config_path << " -> " << output_path << "\n";
    // TODO: 实际生成逻辑
    return 0;
}

// ==================== 主函数 ====================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: lte_tool <command> [args...]\n";
        std::cerr << "Commands:\n";
        std::cerr << "  scan    --band <band> [--force]\n";
        std::cerr << "  gen-sib2 --config <path> --output <path>\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "scan") {
        return handle_scan(argc - 1, argv + 1);
    } else if (cmd == "gen-sib2") {
        return handle_gen_sib2(argc - 1, argv + 1);
    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        return 1;
    }
}