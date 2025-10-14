// lte_tool.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdlib>
#include <sstream>
#include <map>

// nlohmann/json 单头文件（请确保已下载 json.hpp）
#include "json.hpp"
using json = nlohmann::json;

namespace fs = std::filesystem;

// ==================== 工具函数 ====================

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
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
    std::string cmd = "./lib/examples/cell_search -b " + std::to_string(band) + " -a type=x300,time_source=gpsdo";
    std::string output = exec(cmd.c_str());

    // 4. 解析输出（示例解析，你需根据实际输出调整）
    std::vector<json> cells;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("PCI") != std::string::npos) {
            // 示例解析（请根据实际 cell_search 输出格式调整）
            size_t pci_pos = line.find("PCI:");
            size_t freq_pos = line.find("F:");
            if (pci_pos != std::string::npos && freq_pos != std::string::npos) {
                int pci = std::stoi(line.substr(pci_pos + 4, 3));
                double freq = std::stod(line.substr(freq_pos + 2, 8));

                json cell = {
                    {"pci", pci},
                    {"freq_mhz", freq},
                    {"earfcn", 0}, // TODO: 计算 EARFCN
                    {"type", "FDD"} // 可从输出解析
                };
                cells.push_back(cell);
            }
        }
    }

    if (cells.empty()) {
        std::cerr << "❌ No cells found in band " << band << "\n";
        return 1;
    }

    // 5. 保存 cells.json
    write_json(cells_json, cells);
    std::cout << "💾 Saved " << cells.size() << " cells to " << cells_json << "\n";

    // 6. 对每个小区，运行 pdsch_ue 获取配置
    for (const auto& cell : cells) {
        int pci = cell["pci"];
        double freq_mhz = cell["freq_mhz"];
        std::string cell_dir = cache_dir + "/cell_" + std::to_string(pci);
        create_dir(cell_dir);

        std::string config_json = cell_dir + "/config.json";
        if (file_exists(config_json) && !force) {
            continue;
        }

        std::cout << "📡 Decoding cell PCI=" << pci << " at " << freq_mhz << " MHz\n";
        std::string pdsch_cmd = "./lib/examples/pdsch_ue -f " + std::to_string(freq_mhz * 1e6) + " -d";
        int ret = std::system(pdsch_cmd.c_str());
        if (ret != 0) {
            std::cerr << "❌ pdsch_ue failed for PCI " << pci << "\n";
            continue;
        }

        // 假设 pdsch_ue 会生成 output/mib.json, output/sib1.json 等
        if (file_exists("../output/mib.json")) {
            json mib = read_json("../output/mib.json");
            write_json(cell_dir + "/mib.json", mib);

            json config = {
                {"nof_prb", mib["nof_prb"]},
                {"nof_ports", mib["nof_ports"]},
                {"cell_id", pci},
                {"cyclic_prefix", mib["cp"] == "normal" ? "SRSRAN_CP_NORM" : "SRSRAN_CP_EXT"},
                {"phich_length", mib["phich_length"] == "normal" ? "SRSRAN_PHICH_NORM" : "SRSRAN_PHICH_EXT"},
                {"phich_resources", "SRSRAN_PHICH_R_1"}, // TODO: 从 MIB 解析
                {"duplex_mode", "SRSRAN_FDD"} // TODO: 从 MIB
            };
            write_json(config_json, config);

            // 复制 hex 文件
            if (file_exists("../output/mib.hex")) {
                fs::copy_file("../output/mib.hex", cell_dir + "/mib.hex", fs::copy_options::overwrite_existing);
            }
            if (file_exists("../output/sib1.hex")) {
                fs::copy_file("../output/sib1.hex", cell_dir + "/sib1.hex", fs::copy_options::overwrite_existing);
            }
            if (file_exists("../output/sib2.hex")) {
                fs::copy_file("../output/sib2.hex", cell_dir + "/sib2.hex", fs::copy_options::overwrite_existing);
            }
        }
    }

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