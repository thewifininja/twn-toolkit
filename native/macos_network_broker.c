#define _DARWIN_C_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <grp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUEST_HEADER_SIZE 16
#define MAX_HOST_LENGTH 255
#define MAX_TIMEOUT_MS 30000U
#define MIN_TIMEOUT_MS 100U
#define MAX_CHILDREN 256
#define SETUP_LIFETIME_SECONDS 35
#define RELAY_LIFETIME_SECONDS 3700
#define RELAY_BUFFER_SIZE 65536

static volatile sig_atomic_t stopping = 0;
static int listener_fd = -1;
static const char *socket_path = NULL;
static uid_t allowed_uid = (uid_t)-1;
static gid_t allowed_gid = (gid_t)-1;
static volatile sig_atomic_t active_children = 0;

struct relay_buffer {
    unsigned char data[RELAY_BUFFER_SIZE];
    size_t start;
    size_t end;
    int source_eof;
    int target_shutdown;
};

static uint16_t read_u16(const unsigned char *value) {
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static uint32_t read_u32(const unsigned char *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | (uint32_t)value[3];
}

static int read_exact(int descriptor, void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    while (length > 0) {
        ssize_t count = recv(descriptor, cursor, length, 0);
        if (count == 0) return ECONNRESET;
        if (count < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        cursor += count;
        length -= (size_t)count;
    }
    return 0;
}

static int send_result(int descriptor, int error_code, int connected_fd) {
    uint32_t status = htonl((uint32_t)error_code);
    struct iovec payload = {.iov_base = &status, .iov_len = sizeof(status)};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &payload;
    message.msg_iovlen = 1;

    unsigned char control[CMSG_SPACE(sizeof(int))];
    if (error_code == 0 && connected_fd >= 0) {
        memset(control, 0, sizeof(control));
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &connected_fd, sizeof(int));
    }

    while (sendmsg(descriptor, &message, 0) < 0) {
        if (errno != EINTR) return errno;
    }
    return 0;
}

static int set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
        return errno;
    }
    return 0;
}

static size_t relay_buffer_size(const struct relay_buffer *buffer) {
    return buffer->end - buffer->start;
}

static void compact_relay_buffer(struct relay_buffer *buffer) {
    if (buffer->start == buffer->end) {
        buffer->start = 0;
        buffer->end = 0;
    } else if (buffer->end == sizeof(buffer->data) && buffer->start > 0) {
        size_t length = relay_buffer_size(buffer);
        memmove(buffer->data, buffer->data + buffer->start, length);
        buffer->start = 0;
        buffer->end = length;
    }
}

static int read_relay_data(int descriptor, struct relay_buffer *buffer) {
    compact_relay_buffer(buffer);
    if (buffer->source_eof || buffer->end == sizeof(buffer->data)) return 0;
    ssize_t count = recv(
        descriptor,
        buffer->data + buffer->end,
        sizeof(buffer->data) - buffer->end,
        0
    );
    if (count > 0) {
        buffer->end += (size_t)count;
        return 0;
    }
    if (count == 0 || errno == ECONNRESET) {
        buffer->source_eof = 1;
        return 0;
    }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return 0;
    return errno;
}

static int write_relay_data(int descriptor, struct relay_buffer *buffer) {
    size_t length = relay_buffer_size(buffer);
    if (length == 0) return 0;
    ssize_t count = send(descriptor, buffer->data + buffer->start, length, 0);
    if (count > 0) {
        buffer->start += (size_t)count;
        compact_relay_buffer(buffer);
        return 0;
    }
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
        return 0;
    }
    return count < 0 ? errno : EPIPE;
}

static int finish_relay_direction(int descriptor, struct relay_buffer *buffer) {
    if (!buffer->source_eof || relay_buffer_size(buffer) != 0 || buffer->target_shutdown) {
        return 0;
    }
    if (shutdown(descriptor, SHUT_WR) != 0 && errno != ENOTCONN && errno != EINVAL) {
        return errno;
    }
    buffer->target_shutdown = 1;
    return 0;
}

static int relay_streams(int local_fd, int remote_fd) {
    int error_code = set_nonblocking(local_fd);
    if (error_code == 0) error_code = set_nonblocking(remote_fd);
    if (error_code != 0) return error_code;

    struct relay_buffer to_remote;
    struct relay_buffer to_local;
    memset(&to_remote, 0, sizeof(to_remote));
    memset(&to_local, 0, sizeof(to_local));

    while (1) {
        error_code = finish_relay_direction(remote_fd, &to_remote);
        if (error_code == 0) error_code = finish_relay_direction(local_fd, &to_local);
        if (error_code != 0) return error_code;
        if (to_remote.target_shutdown && to_local.target_shutdown) return 0;

        compact_relay_buffer(&to_remote);
        compact_relay_buffer(&to_local);
        struct pollfd waiters[2];
        waiters[0].fd = local_fd;
        waiters[0].events = 0;
        waiters[0].revents = 0;
        waiters[1].fd = remote_fd;
        waiters[1].events = 0;
        waiters[1].revents = 0;
        if (!to_remote.source_eof && to_remote.end < sizeof(to_remote.data)) {
            waiters[0].events |= POLLIN;
        }
        if (relay_buffer_size(&to_local) > 0) waiters[0].events |= POLLOUT;
        if (!to_local.source_eof && to_local.end < sizeof(to_local.data)) {
            waiters[1].events |= POLLIN;
        }
        if (relay_buffer_size(&to_remote) > 0) waiters[1].events |= POLLOUT;

        int ready;
        do {
            ready = poll(waiters, 2, -1);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0) return errno;
        if ((waiters[0].revents | waiters[1].revents) & POLLNVAL) return EBADF;
        if ((waiters[0].revents | waiters[1].revents) & POLLERR) return EIO;

        if (waiters[0].revents & (POLLIN | POLLHUP)) {
            error_code = read_relay_data(local_fd, &to_remote);
        }
        if (error_code == 0 && waiters[1].revents & (POLLIN | POLLHUP)) {
            error_code = read_relay_data(remote_fd, &to_local);
        }
        if (error_code == 0 && waiters[0].revents & POLLOUT) {
            error_code = write_relay_data(local_fd, &to_local);
        }
        if (error_code == 0 && waiters[1].revents & POLLOUT) {
            error_code = write_relay_data(remote_fd, &to_remote);
        }
        if (error_code != 0) return error_code;
    }
}

static int drop_relay_privileges(void) {
    gid_t groups[1] = {allowed_gid};
    if (setgroups(1, groups) != 0 || setgid(allowed_gid) != 0 ||
        setuid(allowed_uid) != 0) {
        return errno;
    }
    if (geteuid() != allowed_uid || getegid() != allowed_gid) return EACCES;
    return 0;
}

static int connect_one(const struct addrinfo *address, uint32_t timeout_ms) {
    int descriptor = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (descriptor < 0) return -1;
    (void)fcntl(descriptor, F_SETFD, FD_CLOEXEC);

    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
        int saved = errno;
        close(descriptor);
        errno = saved;
        return -1;
    }

    if (connect(descriptor, address->ai_addr, address->ai_addrlen) < 0) {
        if (errno != EINPROGRESS) {
            int saved = errno;
            close(descriptor);
            errno = saved;
            return -1;
        }
        struct pollfd waiter = {.fd = descriptor, .events = POLLOUT};
        int ready;
        do {
            ready = poll(&waiter, 1, (int)timeout_ms);
        } while (ready < 0 && errno == EINTR);
        if (ready == 0) {
            close(descriptor);
            errno = ETIMEDOUT;
            return -1;
        }
        if (ready < 0) {
            int saved = errno;
            close(descriptor);
            errno = saved;
            return -1;
        }
        int socket_error = 0;
        socklen_t error_length = sizeof(socket_error);
        if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) < 0) {
            int saved = errno;
            close(descriptor);
            errno = saved;
            return -1;
        }
        if (socket_error != 0) {
            close(descriptor);
            errno = socket_error;
            return -1;
        }
    }

    if (fcntl(descriptor, F_SETFL, flags) < 0) {
        int saved = errno;
        close(descriptor);
        errno = saved;
        return -1;
    }
    return descriptor;
}

static int connect_target(
    const char *host,
    uint16_t port,
    unsigned char family,
    uint32_t timeout_ms
) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family == 4 ? AF_INET : family == 6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char service[6];
    snprintf(service, sizeof(service), "%u", (unsigned int)port);
    struct addrinfo *addresses = NULL;
    int result = getaddrinfo(host, service, &hints, &addresses);
    if (result != 0) {
        errno = result == EAI_SYSTEM ? errno : EHOSTUNREACH;
        return -1;
    }

    int descriptor = -1;
    int last_error = EHOSTUNREACH;
    for (struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        descriptor = connect_one(address, timeout_ms);
        if (descriptor >= 0) break;
        last_error = errno;
    }
    freeaddrinfo(addresses);
    if (descriptor < 0) errno = last_error;
    return descriptor;
}

static void handle_client(int descriptor) {
    uid_t peer_uid = (uid_t)-1;
    gid_t peer_gid = (gid_t)-1;
    if (getpeereid(descriptor, &peer_uid, &peer_gid) != 0 || peer_uid != allowed_uid) {
        (void)send_result(descriptor, EACCES, -1);
        return;
    }

    unsigned char header[REQUEST_HEADER_SIZE];
    int error_code = read_exact(descriptor, header, sizeof(header));
    if (error_code != 0) {
        (void)send_result(descriptor, error_code, -1);
        return;
    }
    if (memcmp(header, "TWNB", 4) != 0 || header[4] != 1 ||
        (header[5] != 0 && header[5] != 4 && header[5] != 6) ||
        header[6] != 1 || header[7] != 0) {
        (void)send_result(descriptor, EPROTO, -1);
        return;
    }

    uint32_t timeout_ms = read_u32(header + 8);
    uint16_t port = read_u16(header + 12);
    uint16_t host_length = read_u16(header + 14);
    if (timeout_ms < MIN_TIMEOUT_MS || timeout_ms > MAX_TIMEOUT_MS || port == 0 ||
        host_length == 0 || host_length > MAX_HOST_LENGTH) {
        (void)send_result(descriptor, EINVAL, -1);
        return;
    }

    char host[MAX_HOST_LENGTH + 1];
    error_code = read_exact(descriptor, host, host_length);
    if (error_code != 0) {
        (void)send_result(descriptor, error_code, -1);
        return;
    }
    host[host_length] = '\0';
    if (memchr(host, '\0', host_length) != NULL) {
        (void)send_result(descriptor, EINVAL, -1);
        return;
    }

    int connected_fd = connect_target(host, port, header[5], timeout_ms);
    if (connected_fd < 0) {
        (void)send_result(descriptor, errno, -1);
        return;
    }

    int relay_pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, relay_pair) != 0) {
        error_code = errno;
        close(connected_fd);
        (void)send_result(descriptor, error_code, -1);
        return;
    }
    (void)fcntl(relay_pair[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(relay_pair[1], F_SETFD, FD_CLOEXEC);

    error_code = drop_relay_privileges();
    if (error_code != 0) {
        close(relay_pair[0]);
        close(relay_pair[1]);
        close(connected_fd);
        (void)send_result(descriptor, error_code, -1);
        return;
    }
    error_code = send_result(descriptor, 0, relay_pair[0]);
    close(relay_pair[0]);
    if (error_code == 0) {
        alarm(RELAY_LIFETIME_SECONDS);
        (void)relay_streams(relay_pair[1], connected_fd);
    }
    close(relay_pair[1]);
    close(connected_fd);
}

static void stop_handler(int signal_number) {
    (void)signal_number;
    stopping = 1;
    if (listener_fd >= 0) close(listener_fd);
}

static void child_handler(int signal_number) {
    (void)signal_number;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (active_children > 0) active_children--;
    }
    errno = saved_errno;
}

static int parse_unsigned(const char *value, unsigned long maximum, unsigned long *parsed) {
    char *end = NULL;
    errno = 0;
    unsigned long result = strtoul(value, &end, 10);
    if (errno != 0 || value[0] == '\0' || end == NULL || *end != '\0' || result > maximum) {
        return EINVAL;
    }
    *parsed = result;
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s --socket PATH --uid UID --gid GID\n", program);
}

int main(int argc, char **argv) {
    const char *uid_text = NULL;
    const char *gid_text = NULL;
    for (int index = 1; index < argc; index++) {
        if (index + 1 >= argc) {
            usage(argv[0]);
            return 2;
        }
        if (strcmp(argv[index], "--socket") == 0) socket_path = argv[++index];
        else if (strcmp(argv[index], "--uid") == 0) uid_text = argv[++index];
        else if (strcmp(argv[index], "--gid") == 0) gid_text = argv[++index];
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (socket_path == NULL || uid_text == NULL || gid_text == NULL || geteuid() != 0) {
        usage(argv[0]);
        return 2;
    }

    unsigned long uid_value = 0;
    unsigned long gid_value = 0;
    if (parse_unsigned(uid_text, UINT32_MAX, &uid_value) != 0 ||
        parse_unsigned(gid_text, UINT32_MAX, &gid_value) != 0 || uid_value == 0) {
        fprintf(stderr, "Invalid non-root service uid or gid.\n");
        return 2;
    }
    allowed_uid = (uid_t)uid_value;
    allowed_gid = (gid_t)gid_value;

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        fprintf(stderr, "Unix socket path is too long.\n");
        return 2;
    }
    strlcpy(address.sun_path, socket_path, sizeof(address.sun_path));

    umask(077);
    unlink(socket_path);
    listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        perror("socket");
        return 1;
    }
    (void)fcntl(listener_fd, F_SETFD, FD_CLOEXEC);
    if (bind(listener_fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chown(socket_path, allowed_uid, allowed_gid) != 0 ||
        chmod(socket_path, 0600) != 0 || listen(listener_fd, 128) != 0) {
        perror("network broker setup");
        close(listener_fd);
        unlink(socket_path);
        return 1;
    }

    struct sigaction stop_action;
    memset(&stop_action, 0, sizeof(stop_action));
    stop_action.sa_handler = stop_handler;
    sigemptyset(&stop_action.sa_mask);
    sigaction(SIGTERM, &stop_action, NULL);
    sigaction(SIGINT, &stop_action, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct sigaction child_action;
    memset(&child_action, 0, sizeof(child_action));
    child_action.sa_handler = child_handler;
    child_action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&child_action.sa_mask);
    sigaction(SIGCHLD, &child_action, NULL);

    sigset_t child_signal;
    sigemptyset(&child_signal);
    sigaddset(&child_signal, SIGCHLD);

    while (!stopping) {
        int client_fd = accept(listener_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR || stopping) continue;
            perror("accept");
            break;
        }
        (void)fcntl(client_fd, F_SETFD, FD_CLOEXEC);
        if (active_children >= MAX_CHILDREN) {
            (void)send_result(client_fd, EBUSY, -1);
            close(client_fd);
            continue;
        }
        sigset_t previous_signals;
        sigprocmask(SIG_BLOCK, &child_signal, &previous_signals);
        pid_t child = fork();
        if (child == 0) {
            sigprocmask(SIG_SETMASK, &previous_signals, NULL);
            close(listener_fd);
            listener_fd = -1;
            alarm(SETUP_LIFETIME_SECONDS);
            handle_client(client_fd);
            close(client_fd);
            _exit(0);
        }
        if (child > 0) active_children++;
        else perror("fork");
        sigprocmask(SIG_SETMASK, &previous_signals, NULL);
        close(client_fd);
    }

    if (listener_fd >= 0) close(listener_fd);
    unlink(socket_path);
    return 0;
}
