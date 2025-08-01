#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <glob.h>

#define MAX_LINE 256
#define SYS_PCI_DEVICES "/sys/bus/pci/devices/"
#define TIMESTAMP_FILE "timestamp"
#define REBOOTCOUNT_FILE "rebootcount"
#define INITIAL_PCI_DEVICES "initial_pci_devices.txt"
#define REBOOT_LOG "reboot.log"

volatile sig_atomic_t stop_flag = 0;

// SIGINT 信號處理函式
void handle_sigint(int sig);
int file_exists(const char *filename);
void write_timestamp(int hours);
time_t read_timestamp();
int update_rebootcount();
void log_initial_info(FILE *log_fp, int reboot_count);
char **fetch_pci_bdfs(int *count);
void free_pci_bdfs(char **bdfs, int count);
void execute_lspci(const char *bfd, const char *suffix);
void run_command_to_file(const char *command, const char *filename);
void compare_and_log(const char *init_file, const char *current_file, const char *bfd, FILE *log_fp);
int create_reboot_script(int argc, char *argv[]);
int setup_systemd_service(void);
void disable_selinux();
void get_current_timestamp(char *buffer, size_t buffer_size);
int validate_input_parameters(int wait_hours, int wait_seconds, int standby_time);
void setup_signal_handlers();
void reset_lpot_directory();

// SIGINT 信號處理函式
void handle_sigint(__attribute__((unused)) int sig) {
    stop_flag = 1;
    printf("\nReceived interrupt signal. Cleaning up...\n");
}

// 設置信號處理器
void setup_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to setup SIGINT handler");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("Failed to setup SIGTERM handler");
    }
}

// 驗證輸入參數
int validate_input_parameters(int wait_hours, int wait_seconds, int standby_time) {
    if (wait_hours < 1 || wait_hours > 8760) {  // 1小時到1年
        fprintf(stderr, "Error: wait_hours must be between 1 and 8760\n");
        return 0;
    }
    if (wait_seconds < 10 || wait_seconds > 3600) {  // 10秒到1小時
        fprintf(stderr, "Error: wait_seconds must be between 10 and 3600\n");
        return 0;
    }
    if (standby_time < 10 || standby_time > 3600) {  // 10秒到1小時
        fprintf(stderr, "Error: standby_time must be between 10 and 3600\n");
        return 0;
    }
    return 1;
}

// 檔案是否存在
int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

// 獲取當前時間戳字符串的輔助函數
void get_current_timestamp(char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return;
    }
    
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    if (timeinfo) {
        strftime(buffer, buffer_size, "%Y/%m/%d %H:%M:%S", timeinfo);
    } else {
        snprintf(buffer, buffer_size, "Unknown time");
    }
}

// 關閉 SELinux 的函數
void disable_selinux() {
    // 先檢查 SELinux 配置檔是否存在
    if (access("/etc/selinux/config", F_OK) != 0) {
        // 配置檔不存在，直接返回不做任何處理
        return;
    }

    FILE *selinux_file = fopen("/etc/selinux/config", "r+");
    if (!selinux_file) {
        // 如果打開失敗，也直接返回
        return;
    }

    char buffer[1024];
    long pos = 0;

    // 暫時關閉 SELinux - 使用安全的 fork/exec
    pid_t pid = fork();
    if (pid == 0) {
        execl("/usr/sbin/setenforce", "setenforce", "0", NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        // 忽略錯誤，因為 SELinux 可能已經被禁用
    }

    // 修改配置檔
    while (fgets(buffer, sizeof(buffer), selinux_file)) {
        if (strstr(buffer, "SELINUX=enforcing")) {
            pos = ftell(selinux_file) - strlen(buffer);
            fseek(selinux_file, pos, SEEK_SET);
            fputs("SELINUX=disabled\n", selinux_file);
            break;
        }
    }

    fclose(selinux_file);
}

// 寫入 timestamp
void write_timestamp(int hours) {
    FILE *fp = fopen(TIMESTAMP_FILE, "w");
    if (!fp) {
        perror("Failed to write timestamp file");
        exit(EXIT_FAILURE);
    }
    time_t now = time(NULL) + hours * 3600;
    fprintf(fp, "%ld\n", now);
    fclose(fp);
}

// 讀取 timestamp
time_t read_timestamp() {
    FILE *fp = fopen(TIMESTAMP_FILE, "r");
    if (!fp) {
        perror("Failed to read timestamp file");
        exit(EXIT_FAILURE);
    }
    time_t timestamp = 0;
    if (fscanf(fp, "%ld", &timestamp) != 1) {
        fprintf(stderr, "Failed to read timestamp from file\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    return timestamp;
}

// 更新或初始化 rebootcount
int update_rebootcount() {
    int count = 1;

    // 嘗試打開文件
    FILE *fp = fopen(REBOOTCOUNT_FILE, "r");
    if (fp) {
        // 如果文件存在，讀取當前值
        if (fscanf(fp, "%d", &count) != 1) {
            fprintf(stderr, "Failed to read reboot count from file, using default value 1\n");
            count = 1;
        } else {
            count++;  // 增加重啟次數
        }
        fclose(fp);

        // 再次打開文件以寫入新值
        fp = fopen(REBOOTCOUNT_FILE, "w");
        if (!fp) {
            perror("Failed to update rebootcount file");
            exit(EXIT_FAILURE);
        }
        fprintf(fp, "%d\n", count);
        fclose(fp);
    } else {
        // 如果文件不存在，創建文件並初始化為 1
        fp = fopen(REBOOTCOUNT_FILE, "w");
        if (!fp) {
            perror("Failed to create rebootcount file");
            exit(EXIT_FAILURE);
        }
        fprintf(fp, "%d\n", count);
        fclose(fp);
    }

    return count;
}

// 記錄初始測試訊息
void log_initial_info(FILE *log_fp, int reboot_count) {
    char time_str[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y/%m/%d %H:%M:%S", tm_info);
    fprintf(log_fp, "\n\n%s #########Start to test#########\n", time_str);
    fprintf(log_fp, "\t\t\tReboot Count: %d\n", reboot_count);
    fflush(log_fp);
}

// 從 /sys/bus/pci/devices/ 提取 PCI BDF
char **fetch_pci_bdfs(int *count) {
    DIR *dir = opendir(SYS_PCI_DEVICES);
    if (!dir) {
        perror("Failed to open PCI devices directory");
        exit(EXIT_FAILURE);
    }
    struct dirent *entry;
    char **bdfs = NULL;
    *count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char **temp = realloc(bdfs, (*count + 1) * sizeof(char *));
        if (!temp) {
            fprintf(stderr, "Memory allocation failed for BDF list\n");
            // 釋放已分配的記憶體
            for (int i = 0; i < *count; i++) {
                free(bdfs[i]);
            }
            free(bdfs);
            closedir(dir);
            exit(EXIT_FAILURE);
        }
        bdfs = temp;

        bdfs[*count] = strdup(entry->d_name);
        if (!bdfs[*count]) {
            fprintf(stderr, "Memory allocation failed for BDF string\n");
            // 釋放已分配的記憶體
            for (int i = 0; i < *count; i++) {
                free(bdfs[i]);
            }
            free(bdfs);
            closedir(dir);
            exit(EXIT_FAILURE);
        }
        (*count)++;
    }
    closedir(dir);
    return bdfs;
}

// 釋放 BDF 清單
void free_pci_bdfs(char **bdfs, int count) {
    for (int i = 0; i < count; i++) {
        free(bdfs[i]);
    }
    free(bdfs);
}

// 執行 lspci 測試 - 安全版本使用 fork/exec
void execute_lspci(const char *bdf, const char *suffix) {
    char filename[256];

    // 構建輸出檔案名
    snprintf(filename, sizeof(filename), "%s%s", bdf, suffix);

    // 驗證 BDF 格式，防止命令注入
    if (!bdf || strlen(bdf) == 0 || strchr(bdf, ';') || strchr(bdf, '&') ||
        strchr(bdf, '|') || strchr(bdf, '`') || strchr(bdf, '$')) {
        fprintf(stderr, "Invalid BDF format: %s\n", bdf);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // 子進程：重定向輸出到檔案
        FILE *output = fopen(filename, "w");
        if (output) {
            dup2(fileno(output), STDOUT_FILENO);
            fclose(output);
        }
        execl("/usr/bin/lspci", "lspci", "-s", bdf, "-vv", NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Warning: lspci command failed for BDF %s\n", bdf);
        }
    } else {
        perror("Fork failed in execute_lspci");
    }
}

// 創建或更新 reboot.sh 腳本的函數
int create_reboot_script(int argc, char *argv[]) {
    const char *script_path = "/lpot/reboot.sh";
    FILE *script_file;

    // 檢查輸入參數
    if (argc < 1 || !argv) {
        fprintf(stderr, "Invalid arguments to create_reboot_script\n");
        return -1;
    }

    // 檢查 /lpot/reboot.sh 是否存在，如果不存在則創建
    if (access(script_path, F_OK) != 0) {
        // 打開或創建腳本檔案
        script_file = fopen(script_path, "w");
        if (!script_file) {
            perror("Failed to create script file");
            return -1;
        }

        // 動態生成執行參數 - 安全版本
        char exec_args[256] = "";
        size_t remaining = sizeof(exec_args) - 1;
        for (int i = 1; i < argc && remaining > 0; i++) {
            if (!argv[i]) {
                fprintf(stderr, "Warning: NULL argument encountered\n");
                continue;
            }
            
            // 驗證參數不包含危險字符
            if (strchr(argv[i], ';') || strchr(argv[i], '&') || 
                strchr(argv[i], '|') || strchr(argv[i], '`') || 
                strchr(argv[i], '$') || strchr(argv[i], '\n') || 
                strchr(argv[i], '\r')) {
                fprintf(stderr, "Warning: Dangerous characters in argument, skipping: %s\n", argv[i]);
                continue;
            }
            
            size_t arg_len = strlen(argv[i]);
            if (arg_len + 1 < remaining) {  // +1 for space
                strncat(exec_args, argv[i], remaining);
                remaining -= arg_len;
                if (remaining > 0) {
                    strncat(exec_args, " ", remaining);
                    remaining--;
                }
            } else {
                fprintf(stderr, "Warning: Command line arguments truncated\n");
                break;
            }
        }

        // 寫入腳本內容
        fprintf(script_file, "#!/bin/bash\n");
        fprintf(script_file, "lpot %s\n", exec_args);
        fclose(script_file);

        // 確保腳本有執行權限
        if (chmod(script_path, 0755) != 0) {
            perror("Failed to set script permissions");
            return -1;
        }

        printf("Created /lpot/reboot.sh with current parameters\n");
    }

    return 0;
}

int setup_systemd_service(void) {
    const char *service_path = "/etc/systemd/system/lpot_reboot.service";
    const char *script_path = "/lpot/reboot.sh";
    FILE *service_file;

    // 檢查 systemd 服務是否已存在
    if (access(service_path, F_OK) != 0) {
        // 打開 systemd 服務檔案
        service_file = fopen(service_path, "w");
        if (!service_file) {
            perror("Failed to create systemd service file");
            return -1;
        }

        // 寫入 systemd 服務設置
        fprintf(service_file, "[Unit]\n");
        fprintf(service_file, "Description=The systemd setup file for PCIE check\n");
        fprintf(service_file, "After=graphical.target\n\n");

        fprintf(service_file, "[Service]\n");
        fprintf(service_file, "ExecStart=%s\n", script_path);
        fprintf(service_file, "Restart=no\n");
        fprintf(service_file, "User=root\n");
        fprintf(service_file, "Group=root\n");
        fprintf(service_file, "WorkingDirectory=/lpot\n\n");

        fprintf(service_file, "[Install]\n");
        fprintf(service_file, "WantedBy=graphical.target\n");

        fclose(service_file);

        // 檢查並關閉 SELinux
        disable_selinux();

        // 執行 systemctl daemon-reload
        pid_t pid = fork();
        if (pid == 0) {
            execl("/bin/systemctl", "systemctl", "daemon-reload", NULL);
            exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                fprintf(stderr, "Failed to reload systemd daemon\n");
                return -1;
            }
        } else {
            perror("Fork failed");
            return -1;
        }

        // 執行 systemctl enable
        pid = fork();
        if (pid == 0) {
            execl("/bin/systemctl", "systemctl", "enable", "lpot_reboot.service", NULL);
            exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                fprintf(stderr, "Failed to enable lpot_reboot service\n");
                return -1;
            }
        } else {
            perror("Fork failed");
            return -1;
        }
    }

    return 0;
}


// 檢查 init_file 中是否包含指定的 BDF
int init_file_contains_bdf(const char *target_bdf) {
    DIR *dir;
    struct dirent *entry;

    // 打開目錄
    dir = opendir("/lpot/");
    if (!dir) {
        perror("opendir failed");
        return 0; // 無法檢查，假設不包含
    }

    // 遍歷目錄中的所有檔案
    while ((entry = readdir(dir)) != NULL) {
        // 檢查檔名是否以 "_init.txt" 結尾
        char *suffix = strstr(entry->d_name, "_init.txt");
        if (suffix && suffix[9] == '\0') {
            // 計算 BDF 部分的長度
            size_t bdf_length = suffix - entry->d_name;

            // 比對目錄中的 BDF 是否等於目標 BDF
            if (strlen(target_bdf) == bdf_length &&
                strncmp(entry->d_name, target_bdf, bdf_length) == 0) {
                closedir(dir);
                return 1; // 找到對應的 BDF，表示目標 BDF 存在於系統中
            }
        }
    }

    closedir(dir);
    return 0; // 沒有找到對應的 BDF，表示目標 BDF 不存在於系統中
}

// 刪除所有當前的 <bdf>.txt 結果檔案，但保留 <bdf>_init.txt 和 initial_pci_devices.txt 文件
void cleanup_bdf_files() {
    DIR *dir;
    struct dirent *entry;
    char current_file[256];
    int files_removed = 0;

    // 打開目錄
    dir = opendir("/lpot/");
    if (!dir) {
        perror("opendir failed");
        return;
    }

    // 讀取目錄中的所有檔案
    while ((entry = readdir(dir)) != NULL) {
        // 檢查檔名是否結尾是 .txt 且不是 _init.txt 或 initial_pci_devices.txt
        if (strlen(entry->d_name) > 4 && strcmp(entry->d_name + strlen(entry->d_name) - 4, ".txt") == 0 &&
            strstr(entry->d_name, "_init") == NULL && strcmp(entry->d_name, "initial_pci_devices.txt") != 0 &&
            strcmp(entry->d_name, "ignore_bits.txt") != 0) {

            snprintf(current_file, sizeof(current_file), "/lpot/%s", entry->d_name);

            if (file_exists(current_file)) {
                if (remove(current_file) == 0) {
                    files_removed++;
                } else {
                    perror("Failed to remove file");
                }
            }
        }
    }

    // 如果有刪除文件，立即退出
    if (files_removed > 0) {
        printf("Total %d files cleaned up.\n", files_removed);
    }

    closedir(dir);
}

// 停止 systemd 服務 - 安全版本使用 execl
int stop_systemd_service(const char *service_name) {
    // 驗證服務名稱，防止命令注入
    if (!service_name || strlen(service_name) == 0 || strchr(service_name, ';') ||
        strchr(service_name, '&') || strchr(service_name, '|') || strchr(service_name, '`')) {
        fprintf(stderr, "Invalid service name\n");
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/systemctl", "systemctl", "stop", service_name, NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Systemctl stop command failed with status %d\n", WEXITSTATUS(status));
            return -1;
        }
    } else {
        perror("Fork failed");
        return -1;
    }
    return 0;
}

void show_help(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Version: 1.2.6\n");
    printf("Author: Nephom,Chiang\n");
    printf("OPTIONS:\n");
    printf("  -t <hours>   Setup runtime, default is 12 hours.\n");
    printf("  -d <secs>    Setup delay time for reboot, default is 300 seconds.\n");
    printf("  -s <secs>    Setup delay time for driver ready, default is 300 seconds.\n");
    printf("  -p           Set stop flag when Error occurred!\n");
    printf("  -r           Reset /lpot directory and clean all files.\n");
    printf("  -h, --help   Show Help menu\n");
    printf("\nExample:\n");
    printf("  %s -t 24 -d 600    Run reboot during 24 hours and each reboot wait for 600 seconds\n", program_name);
    printf("  %s -r              Reset /lpot directory to clean state\n", program_name);
}

void filter_lpotscan_errors(const char *error_log_path, FILE *log_fp) {
    FILE *errorLog = fopen(error_log_path, "r");
    if (!errorLog) {
        perror("Failed to open error log");
        return;
    }

    char buffer[MAX_LINE];
    int write_line = 0;

    while (fgets(buffer, sizeof(buffer), errorLog)) {
        // 避免 "No devices changed" 這類無意義訊息
        if (strstr(buffer, "No devices changed")) {
            continue;
        }

        // 只要是有 '|' 符號的行，代表是設備變更資訊
        char *bdf_start = strchr(buffer, '|');
        if (bdf_start) {
            fprintf(log_fp, "%s", buffer); // 直接寫入 log_fp
            write_line = 1;
        } else if (write_line) {
            // 如果前面有輸出過一行 BDF 資訊，則允許繼續輸出變更內容
            if (strstr(buffer, "Before") || strstr(buffer, "After") || strstr(buffer, "Differences")) {
                fprintf(log_fp, "%s", buffer);
            }
        }
    }

    fclose(errorLog);
}

int process_pci_devices(int bdf_count, char **bdfs, FILE *log_fp, int stopService) {
    int *results = malloc(bdf_count * sizeof(int));
    if (!results) {
        perror("Failed to allocate memory for results");
        return EXIT_FAILURE;
    }

    char **new_devices = malloc(bdf_count * sizeof(char*));
    if (!new_devices) {
        perror("Failed to allocate memory for new_devices");
        free(results);
        return EXIT_FAILURE;
    }

    char **removed_devices = malloc(bdf_count * sizeof(char*));
    if (!removed_devices) {
        perror("Failed to allocate memory for removed_devices");
        free(results);
        free(new_devices);
        return EXIT_FAILURE;
    }

    int new_count = 0;
    int removed_count = 0;

    glob_t init_files;
    if (glob("*_init.txt", 0, NULL, &init_files) != 0) {
        fprintf(log_fp, "Error finding init files\n");
        free(results);
        free(new_devices);
        free(removed_devices);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < bdf_count; i++) {
        char current_file[64];
        snprintf(current_file, sizeof(current_file), "%s.txt", bdfs[i]);
        execute_lspci(bdfs[i], ".txt");
    }

    for (size_t j = 0; j < init_files.gl_pathc; j++) {
        char *init_file = init_files.gl_pathv[j];
        char bdf[32];
        if (sscanf(init_file, "%31[^_]_init.txt", bdf) != 1) {
            fprintf(stderr, "Warning: Failed to parse BDF from init file: %s\n", init_file);
            continue;
        }
        char current_file[64];
        snprintf(current_file, sizeof(current_file), "%s.txt", bdf);
        FILE *fp = fopen(current_file, "r");
        if (!fp) {
            removed_devices[removed_count] = strdup(bdf);
            if (removed_devices[removed_count] == NULL) {
                fprintf(stderr, "Memory allocation failed for removed device\n");
                continue;
            }
            removed_count++;
            fprintf(log_fp, "REMOVED Device: %s\n", bdf);
        } else {
            fclose(fp);
        }
    }

    for (int i = 0; i < bdf_count; i++) {
        char current_file[64];
        snprintf(current_file, sizeof(current_file), "%s.txt", bdfs[i]);
        int found_in_init = 0;
        for (size_t j = 0; j < init_files.gl_pathc; j++) {
            char *init_file = init_files.gl_pathv[j];
            char bdf[32];
            if (sscanf(init_file, "%31[^_]_init.txt", bdf) != 1) {
                continue;
            }
            if (strcmp(bdf, bdfs[i]) == 0) {
                found_in_init = 1;
                break;
            }
        }
        if (!found_in_init) {
            new_devices[new_count] = strdup(bdfs[i]);
            if (new_devices[new_count] == NULL) {
                fprintf(stderr, "Memory allocation failed for new device\n");
                continue;
            }
            new_count++;
            fprintf(log_fp, "NEW Device: %s\n", bdfs[i]);
        }
    }

    int all_unchanged = (new_count == 0 && removed_count == 0);
    int overall_success = 1;
    if (all_unchanged) {
        FILE *logFile = fopen("/lpot/reboot.log", "a");
        if (!logFile) {
            perror("Failed to open log file");
            // 清理資源
            for (int i = 0; i < new_count; i++) {
                free(new_devices[i]);
            }
            for (int i = 0; i < removed_count; i++) {
                free(removed_devices[i]);
            }
            free(new_devices);
            free(removed_devices);
            free(results);
            globfree(&init_files);
            return EXIT_FAILURE;
        }

        for (int i = 0; i < bdf_count; i++) {
            char init_file[64], current_file[64];
            snprintf(init_file, sizeof(init_file), "%s_init.txt", bdfs[i]);
            snprintf(current_file, sizeof(current_file), "%s.txt", bdfs[i]);
            // 安全地執行 lpotscan
            pid_t lpotscan_pid = fork();
            int result = -1;
            if (lpotscan_pid == 0) {
                execlp("lpotscan", "lpotscan", init_file, current_file, 
                       stopService ? "true" : "false", NULL);
                exit(1);
            } else if (lpotscan_pid > 0) {
                int status;
                waitpid(lpotscan_pid, &status, 0);
                if (WIFEXITED(status)) {
                    result = WEXITSTATUS(status);
                } else {
                    result = -1;
                }
            } else {
                perror("Fork failed for lpotscan");
                result = -1;
            }
            results[i] = result;
            //fprintf(log_fp, "BDF: %s, Result: %d\n", bdfs[i], result);
            if (result != 0) {
                overall_success = 0;
            }
        }

        char timeStr[64];
        get_current_timestamp(timeStr, sizeof(timeStr));

        if (!overall_success) {
            fprintf(logFile, "%s Had devices changed\n", timeStr);
            fflush(logFile); // 確保寫入
            filter_lpotscan_errors("/tmp/lpotscan.log", logFile);
            fflush(logFile); // 再次確保變更內容寫入
            if (stopService) {
                fprintf(logFile, "%s You setting -p parameter, I will stop reboot test.\n", timeStr);
                fflush(logFile);
                exit(EXIT_FAILURE);
            }
        } else {
            fprintf(logFile, "%s No devices changed\n", timeStr);
        }

        fclose(logFile);
    }

    for (int i = 0; i < new_count; i++) {
        free(new_devices[i]);
    }
    for (int i = 0; i < removed_count; i++) {
        free(removed_devices[i]);
    }
    free(new_devices);
    free(removed_devices);
    free(results);
    globfree(&init_files);

    return (all_unchanged) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
    // 確保工作目錄在 /lpot
    struct stat st = {0};
    if (stat("/lpot", &st) == -1) {
        if (mkdir("/lpot", 0755) != 0) {
            perror("Failed to create /lpot directory");
            return EXIT_FAILURE;
        }
    }
    
    if (chdir("/lpot") != 0) {
        perror("Failed to change to /lpot directory");
        return EXIT_FAILURE;
    }

    int wait_hours = 12, wait_seconds = 300, standby_time = 300;
    bool stopService = false;
    int opt;

    // 設置信號處理器
    setup_signal_handlers();

    while ((opt = getopt(argc, argv, "t:d:s:phr")) != -1) {
        switch (opt) {
            case 't':
                wait_hours = atoi(optarg);
                if (wait_hours <= 0) {
                    fprintf(stderr, "Error: Invalid value for -t option\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'd':
                wait_seconds = atoi(optarg);
                if (wait_seconds <= 0) {
                    fprintf(stderr, "Error: Invalid value for -d option\n");
                    return EXIT_FAILURE;
                }
                break;
            case 's':
                standby_time = atoi(optarg);
                if (standby_time <= 0) {
                    fprintf(stderr, "Error: Invalid value for -s option\n");
                    return EXIT_FAILURE;
                }
                break;
            case 'p':
                stopService = true;
                break;
            case 'r':
                reset_lpot_directory();
                return EXIT_SUCCESS;
            case 'h':
                show_help(argv[0]);
                return EXIT_SUCCESS;
            default:
                fprintf(stderr, "Using %s -h check Help\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    // 驗證輸入參數
    if (!validate_input_parameters(wait_hours, wait_seconds, standby_time)) {
        return EXIT_FAILURE;
    }

    // 創建 reboot.sh 腳本（如果不存在）
    if (create_reboot_script(argc, argv) != 0) {
        fprintf(stderr, "Failed to create reboot script. Continuing...\n");
    }

    if (!file_exists(TIMESTAMP_FILE)) {
        write_timestamp(wait_hours);
    } else {
        time_t current_time = time(NULL);
        time_t timestamp = read_timestamp();

        if (current_time >= timestamp) {
            char error_msg[256];

            // 取得當前時間並格式化
            char timestamp_str[64];
            get_current_timestamp(timestamp_str, sizeof(timestamp_str));

            snprintf(error_msg, sizeof(error_msg), "%s Execution halted: timestamp expired.\n", timestamp_str);

            FILE *log_fp = fopen(REBOOT_LOG, "a");
            if (log_fp) {
                fprintf(log_fp, "%s", error_msg);
                fclose(log_fp);
            }

            // 安全地清理臨時文件
            pid_t cleanup_pid = fork();
            if (cleanup_pid == 0) {
                execl("/usr/bin/find", "find", "/lpot/", "-type", "f", "-name", "*.txt", 
                      "!", "-name", "initial_*.txt", "-exec", "rm", "-f", "{}", "+", NULL);
                exit(1);
            } else if (cleanup_pid > 0) {
                int status;
                waitpid(cleanup_pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                    fprintf(stderr, "Warning: Failed to clean up temporary files\n");
                }
            }
            
            // 安全地執行 configscan_log.sh
            pid_t config_pid = fork();
            if (config_pid == 0) {
                execlp("configscan_log.sh", "configscan_log.sh", NULL);
                exit(1);
            } else if (config_pid > 0) {
                int status;
                waitpid(config_pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                    fprintf(stderr, "Warning: Failed to execute configscan_log.sh\n");
                }
            }

            return EXIT_FAILURE;
        }
    }

    if (setup_systemd_service() != 0) {
        fprintf(stderr, "Failed to setup systemd service. Exiting.\n");
        return EXIT_FAILURE;
    }

    int reboot_count = update_rebootcount();
    FILE *log_fp = fopen(REBOOT_LOG, "a");
    if (!log_fp) {
        perror("Failed to open reboot.log");
        return EXIT_FAILURE;
    }

    // 取得當前時間並格式化
    char timestamp_str[64];
    get_current_timestamp(timestamp_str, sizeof(timestamp_str));
    log_initial_info(log_fp, reboot_count);

    // 獲取 PCI 設備列表
    int bdf_count;
    char **bdfs = fetch_pci_bdfs(&bdf_count);

    // 等候 standby_time 秒，但檢查停止信號
    fprintf(log_fp, "%s Wait %d seconds for devices driver ready. \n", timestamp_str, standby_time);
    fflush(log_fp);  // 確保 log 立即寫入
    printf("%s Wait %d seconds for devices driver ready. \n", timestamp_str, standby_time);
    fflush(stdout);

    // 分段睡眠以便響應信號
    for (int i = 0; i < standby_time && !stop_flag; i++) {
        sleep(1);
    }

    if (stop_flag) {
        fprintf(log_fp, "Received stop signal, exiting gracefully.\n");
        fclose(log_fp);
        free_pci_bdfs(bdfs, bdf_count);
        return EXIT_SUCCESS;
    }
    if (bdf_count == 0) {
        fprintf(stderr, "Error: No PCI devices found\n");
        fclose(log_fp);
        free_pci_bdfs(bdfs, bdf_count);
        return EXIT_FAILURE;
    }

    if (!file_exists(INITIAL_PCI_DEVICES)) {
        // 使用安全的方式執行 lspci
        pid_t pid = fork();
        if (pid == 0) {
            FILE *output = fopen(INITIAL_PCI_DEVICES, "w");
            if (output) {
                dup2(fileno(output), STDOUT_FILENO);
                fclose(output);
            }
            execl("/usr/bin/lspci", "lspci", "-vv", NULL);
            exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                fprintf(stderr, "Warning: Initial lspci command failed\n");
            }
        } else {
            perror("Fork failed for initial lspci");
        }

        for (int i = 0; i < bdf_count && !stop_flag; i++) {
            execute_lspci(bdfs[i], "_init.txt");
        }
    }

    // 分析階段
    get_current_timestamp(timestamp_str, sizeof(timestamp_str));
    fprintf(log_fp, "%s Analyzing\n", timestamp_str);
    fflush(log_fp);  // 確保 log 立即寫入
    fprintf(log_fp, "%s Scan Config space...\n", timestamp_str);
    fflush(log_fp);  // 確保 log 立即寫入

    // 安全地執行 configscan
    pid_t configscan_pid = fork();
    if (configscan_pid == 0) {
        execlp("configscan", "configscan", NULL);
        exit(1);
    } else if (configscan_pid > 0) {
        int status;
        waitpid(configscan_pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Warning: configscan command failed\n");
        }
    } else {
        perror("Fork failed for configscan");
    }

    // 掃描完成
    get_current_timestamp(timestamp_str, sizeof(timestamp_str));
    fprintf(log_fp, "%s Scan Done.\n", timestamp_str);

    int result = process_pci_devices(bdf_count, bdfs, log_fp, stopService);
    if (result != EXIT_SUCCESS) {
        // PCI 設備檢查失敗
        get_current_timestamp(timestamp_str, sizeof(timestamp_str));
        fprintf(log_fp, "%s PCI devices check failed\n", timestamp_str);
        fclose(log_fp);
        free_pci_bdfs(bdfs, bdf_count);
        return EXIT_FAILURE;
    }

    cleanup_bdf_files();

    // 準備重啟
    get_current_timestamp(timestamp_str, sizeof(timestamp_str));
    fprintf(log_fp, "%s Wait %d seconds for reboot SUT. \n", timestamp_str, wait_seconds);
    fflush(log_fp);  // 確保 log 立即寫入
    fsync(fileno(log_fp));  // 強制寫入磁碟
    sleep(wait_seconds);
    if (remove("/tmp/lpotscan.log") == 0) {
        printf("File deleted successfully\n");
    } else {
        printf("Error deleting file\n");
    }
    
    // 安全地執行 reboot
    pid_t reboot_pid = fork();
    if (reboot_pid == 0) {
        execl("/sbin/reboot", "reboot", NULL);
        exit(1);
    } else if (reboot_pid > 0) {
        int status;
        waitpid(reboot_pid, &status, 0);
        // reboot 通常不會返回，但為了安全起見還是等待
    } else {
        perror("Fork failed for reboot");
    }
    return 0;
}

// 重置 /lpot 目錄
void reset_lpot_directory() {
    printf("Resetting /lpot directory...\n");
    
    // 檢查 /lpot 目錄是否存在
    struct stat st = {0};
    if (stat("/lpot", &st) == -1) {
        printf("/lpot directory does not exist, creating...\n");
        if (mkdir("/lpot", 0755) != 0) {
            perror("Failed to create /lpot directory");
            exit(EXIT_FAILURE);
        }
    }
    
    // 清空 /lpot 目錄下所有檔案
    pid_t clean_pid = fork();
    if (clean_pid == 0) {
        execl("/usr/bin/find", "find", "/lpot", "-type", "f", "-delete", NULL);
        exit(1);
    } else if (clean_pid > 0) {
        int status;
        waitpid(clean_pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Warning: Failed to clean /lpot directory completely\n");
        }
    } else {
        perror("Fork failed for directory cleanup");
    }
    
    printf("Reset completed. You can now run lpot with normal parameters.\n");
}

