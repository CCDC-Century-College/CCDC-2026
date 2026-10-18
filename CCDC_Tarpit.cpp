// CCDC_Tarpit.cpp

#include "CCDC_Tarpit.h"
#include <iostream>	
#include <fstream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctime>	
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <errno.h>
#include <signal.h>

#include "CCDC_Tarpit.h"

// --- LOG PATH DEFINITIONS ---
#define PRIMARY_LOG_PATH "tarpit_primary.log"

//===================================================================================================================|
// COMPETITION CONFIGURATION PARAMATERS =============================================================================|
//===================================================================================================================|

// 🔒 TRAFFIC CAPACITY CEILING 🔒 
// Maximum number of concurrent attacker connections allowed to be trapped at once.
// Set this based on server RAM/resources.
// VM-RAM 4GB+|150->200|~1.5GB|
// VM-RAM 2GB | 50->100|~600MB|*Default
// VM-RAM 1GB | 25->50 |~300MB|
const int MAX_ALLOWED_TRAPS = 50;

// 📋 PORT CONFIGURATION 📋
// If the the topology map dictates a different target, or if a service port changes mid-comp,

// FTP = 21/2121/2021
// SSH = 22/2222/2200
// HTTP-Based Database Gateway = 8080/3000/5000

// Update this integer. 
const int TARGET_LISTEN_PORT = 8080;

// 🎭 DECEPTIVE BANNER 🎭 (THE BAIT)
// Change this text to match whatever service you want to spoof based on your topology map.

// -For SSH spoofing: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
// -For FTP spoofing: "220 FTP version 1.0 Ready.\r\n"
// -For Database spoofing: "220 Enterprise Database Sync Gateway v2.4 (Initializing buffer...)\r\n"
const std::string DECEPTIVE_SERVICE_BANNER = "220 Enterprise Database Sync Gateway v2.4 (Initializing buffer...)\r\n";


//DONT TOUCH ANYTHING UNDER THIS LINE
//========================================================================================================================
//========================================================================================================================

// --- INTERNAL HARDENING TUNING ---
// Sets a strict 512-byte limit on individual log lines to prevent log-flooding attacks, 
// disk space exhaustion, and memory bloat, protecting the host system from offensive crashes.
const size_t MAX_LOG_LINE_SIZE = 512;

// Atomic counter tracking the total number of active attacker connections currently trapped.
std::atomic<int> active_traps(0);

// Thread-safe registry mapping attacker IP addresses (strings) to vectors of active socket file descriptors (ints).
std::unordered_map<std::string, std::vector<int>> ip_connection_registry;

// Mutex lock to prevent race conditions when multiple threads read or modify the ip_connection_registry.
std::mutex registry_mutex;

// --- GLOBAL LOGGING STATE ---
// Global file handle kept open to avoid repeated open/close cycles
// Protected by a dedicated logging mutex to ensure thread-safe writes
std::mutex log_mutex;
std::ofstream* g_log_file = nullptr;

// --- INITIALIZE LOGGING ---
void initialize_logging() {
    g_log_file = new std::ofstream(PRIMARY_LOG_PATH, std::ios::app);
    if (!g_log_file->is_open()) {
        std::cerr << "[ERROR] Failed to open primary log file: " << PRIMARY_LOG_PATH << "\n";
    }
}

// --- IMPROVED LOGGING FUNCTION ---
void log_local_alert(const std::string& attacker_ip, const std::string& msg_context) {
    
    // Retrieve current system time
    std::time_t now = std::time(nullptr);
    char time_buf[80];

    // Format time into a human-readable string (YYYY-MM-DD HH:MM:SS)
    std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    // Sanitize and cap IP length to prevent injection or formatting distortion
    std::string clean_ip = attacker_ip.substr(0, 45);

    // Sanitize and cap message context length
    std::string clean_msg = msg_context.substr(0, 100);

    // Construct the base log message string
    std::string alert = std::string("[") + time_buf + "] " + clean_msg + " Target: " + clean_ip + "\n";

    // Hard check against MAX_LOG_LINE_SIZE to truncate oversized log strings
    if (alert.length() > MAX_LOG_LINE_SIZE) {
        alert = alert.substr(0, MAX_LOG_LINE_SIZE - 1) + "\n";
    }

    // Immediately output the alert to the console buffer with a flush
    std::cout << "[!!!] " << alert << std::flush;

    // Write to persistent disk log with minimal I/O overhead
    // Use dedicated log_mutex to ensure thread-safe writes
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        if (g_log_file && g_log_file->is_open()) {
            *g_log_file << alert;
            g_log_file->flush();  // Explicit flush for durability
        }
    }
}

// --- CONNECTION UNREGISTRATION ---
// Safely removes a closed socket file descriptor from a specific attacker's IP entry
// within the global connection registry using a thread-safe mutex lock.
void unregister_connection(const std::string& ip, int fd) {
    std::lock_guard<std::mutex> lock(registry_mutex);

    auto it = ip_connection_registry.find(ip);
    if (it != ip_connection_registry.end()) {
        auto& fds = it->second;

        // Iterate through the vector of file descriptors associated with this IP
        for (auto vec_it = fds.begin(); vec_it != fds.end(); ++vec_it) {
            // Match the target file descriptor to remove it
            if (*vec_it == fd) {
                fds.erase(vec_it);
                break;
            }
        }

        // Clean up map entry entirely if the IP no longer has active descriptors
        if (fds.empty()) {
            ip_connection_registry.erase(it);
        }
    }
}

// --- ATTACKER HANDLER & SLOW-DRIP LOOP ---
// Manages the complete lifecycle of an trapped connection: delivers the deceptive banner,
// holds the socket open via a slow trickle loop, and cleans up resource counts on exit.
void handle_attacker(int client_fd, std::string attacker_ip) {
    // RAII CounterGuard struct ensures decrementing active_traps and unregistering 
    // the socket automatically when this function scope exits (even during errors).
    struct CounterGuard {
        std::string ip;
        int fd;
        
        ~CounterGuard() {
            unregister_connection(ip, fd);
            active_traps--;
        }
    } guard{ attacker_ip, client_fd };

    // Transmit the fake enterprise database sync gateway banner to the scanner/attacker
    // Use send() with MSG_NOSIGNAL flag to prevent SIGPIPE if the client has disconnected
    ssize_t banner_sent = send(client_fd, DECEPTIVE_SERVICE_BANNER.c_str(), 
                               DECEPTIVE_SERVICE_BANNER.length(), MSG_NOSIGNAL);
    if (banner_sent < 0) {
        log_local_alert(attacker_ip, "[ERROR] Failed to send banner (SIGPIPE-safe).");
        close(client_fd);
        return;
    }

    // Enter the infinite slow-drip holding loop to waste attacker threads and time
    while (true) {
        // Sleep for 60 seconds between tick intervals to conserve host CPU
        std::this_thread::sleep_for(std::chrono::seconds(60));

        char buf = 0;
        // Non-blocking peek check to see if the remote attacker dropped or closed their connection
        int check = recv(client_fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
        if (check == 0 || (check < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) {
            break; // Exit loop if connection was terminated by remote host
        }

        // Send a single slow-drip character packet to keep TCP window alive and trap active
        // Use send() with MSG_NOSIGNAL flag to prevent SIGPIPE if the client has disconnected
        const char* trickle = ".";
        ssize_t sent = send(client_fd, trickle, 1, MSG_NOSIGNAL);
        if (sent < 0) {
            log_local_alert(attacker_ip, "[DEBUG] Write failed during drip (SIGPIPE-safe).");
            break;
        }
    }

    // Close the client socket file descriptor upon loop exit
    close(client_fd);
}

// --- EVICTION MANAGEMENT (HARDENED) ---
// Uses a two-stage approach: mark for eviction, then gracefully terminate
bool try_evict_redundant_bot() {
    int target_fd_to_kill = -1;
    std::string worst_offender_ip = "";

    // STAGE 1: Find and extract the fd while holding lock
    {
        std::lock_guard<std::mutex> lock(registry_mutex);
        size_t max_connections = 1;

        // Iterate across all registered IPs to find the heaviest connector
        for (const auto& [ip, fds] : ip_connection_registry) {
            if (fds.size() > max_connections) {
                max_connections = fds.size();
                worst_offender_ip = ip;
                target_fd_to_kill = fds.back();
            }
        }

        // If an offender is identified, mark for eviction by removing from registry
        // This prevents handle_attacker() from trying to close it twice
        if (target_fd_to_kill != -1) {
            // Find and remove this fd from the registry NOW while we hold the lock
            auto it = ip_connection_registry.find(worst_offender_ip);
            if (it != ip_connection_registry.end()) {
                auto& fds = it->second;
                for (auto vec_it = fds.begin(); vec_it != fds.end(); ++vec_it) {
                    if (*vec_it == target_fd_to_kill) {
                        fds.erase(vec_it);
                        break;
                    }
                }
                if (fds.empty()) {
                    ip_connection_registry.erase(it);
                }
            }
        }
    } // Lock released here

    // STAGE 2: Close the fd outside the critical section (no lock needed)
    // The fd has been removed from registry, so handle_attacker() won't try to close it
    if (target_fd_to_kill != -1) {
        log_local_alert(worst_offender_ip, "[EVICTION] Dropping redundant connection.");
        shutdown(target_fd_to_kill, SHUT_RDWR);
        close(target_fd_to_kill);
        return true;
    }

    return false;
}

// --- MAIN LISTENER EXECUTION ---
// Initializes network sockets, sets socket options, binds to the configured port, 
// and runs the primary multi-threaded accept loop for incoming connections.
int main() {
    // Initialize centralized logging FIRST
    initialize_logging();

    // === SIGPIPE SAFETY LAYER ===
    // Globally ignore SIGPIPE signals across all worker threads.
    // This prevents the application from crashing when writing to closed sockets.
    // The signal(2) call is thread-safe for this initialization and applies to all threads.
    signal(SIGPIPE, SIG_IGN);
    
    // Create the master listening TCP socket using IPv4
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return 1;

    // Configure server address parameters
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(TARGET_LISTEN_PORT);

    // Allow immediate reuse of local addresses/ports to prevent "Address already in use" binding errors on restart
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind socket to port and set up a listen backlog queue of 100 pending connections
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0 || listen(server_fd, 100) < 0) {
        close(server_fd);
        return 1;
    }

    // Print active status message to standard output console
    std::cout << "[*] Priority Tarpit active on port " << TARGET_LISTEN_PORT
        << " (Cap: " << MAX_ALLOWED_TRAPS << ").\n";

    // Main infinite loop to continuously accept incoming TCP connection attempts
    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        // Accept incoming connection request from a scanner or attacker
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd >= 0) {
            char client_ip[INET_ADDRSTRLEN] = { 0 };

            // Convert binary network address into a standard presentation IP string
            if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip) - 1) == nullptr) {
                close(client_fd);
                continue;
            }
            std::string ip_str(client_ip);

            // Check if active trap capacity has been reached; attempt eviction if true
            if (active_traps >= MAX_ALLOWED_TRAPS) {
                if (!try_evict_redundant_bot()) {
                    close(client_fd); // Drop connection if eviction fails
                    continue;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            // Log the hook event and register the connection securely
            log_local_alert(ip_str, "[ALERT] Tarpit hooked IP.");
            
            // Move active_traps++ INSIDE the mutex lock to prevent race condition
            {
                std::lock_guard<std::mutex> lock(registry_mutex);
                active_traps++;
                ip_connection_registry[ip_str].push_back(client_fd);
            }

            // Detach a dedicated handler thread for this attacker
            std::thread(handle_attacker, client_fd, ip_str).detach();
        }
    }

    // Clean up server file descriptor (unreachable in normal execution, kept for clean syntax)
    close(server_fd);
    
    // Cleanup logging at end
    if (g_log_file) {
        g_log_file->close();
        delete g_log_file;
    }
    
    return 0;
}

