#define RELAY_HALF_CLOSE_IDLE_MS 100
#define main twn_network_broker_program_main
#include "../../native/macos_network_broker.c"
#undef main

static int expect_bytes(int descriptor, const char *expected, size_t length) {
    char buffer[128];
    if (length > sizeof(buffer)) return EINVAL;
    int error_code = read_exact(descriptor, buffer, length);
    if (error_code != 0) return error_code;
    return memcmp(buffer, expected, length) == 0 ? 0 : EIO;
}

int main(void) {
    int application[2] = {-1, -1};
    int remote[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, application) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, remote) != 0) {
        return 1;
    }

    pid_t relay = fork();
    if (relay < 0) return 2;
    if (relay == 0) {
        close(application[0]);
        close(remote[0]);
        alarm(5);
        int error_code = relay_streams(application[1], remote[1]);
        close(application[1]);
        close(remote[1]);
        _exit(error_code == 0 ? 0 : 3);
    }

    close(application[1]);
    close(remote[1]);
    const char client_message[] = "client-to-remote";
    const char server_message[] = "remote-to-client";
    if (send(application[0], client_message, sizeof(client_message), 0) < 0 ||
        expect_bytes(remote[0], client_message, sizeof(client_message)) != 0 ||
        send(remote[0], server_message, sizeof(server_message), 0) < 0 ||
        expect_bytes(application[0], server_message, sizeof(server_message)) != 0) {
        return 4;
    }

    if (shutdown(application[0], SHUT_WR) != 0) return 5;
    char byte = 0;
    if (recv(remote[0], &byte, 1, 0) != 0) return 6;
    if (shutdown(remote[0], SHUT_WR) != 0) return 7;
    if (recv(application[0], &byte, 1, 0) != 0) return 8;

    close(application[0]);
    close(remote[0]);
    int status = 0;
    if (waitpid(relay, &status, 0) != relay) return 9;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 10;

    int abandoned_application[2] = {-1, -1};
    int abandoned_remote[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, abandoned_application) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, abandoned_remote) != 0) {
        return 11;
    }
    relay = fork();
    if (relay < 0) return 12;
    if (relay == 0) {
        close(abandoned_application[0]);
        close(abandoned_remote[0]);
        alarm(2);
        int error_code = relay_streams(
            abandoned_application[1],
            abandoned_remote[1]
        );
        close(abandoned_application[1]);
        close(abandoned_remote[1]);
        _exit(error_code == 0 ? 0 : 13);
    }
    close(abandoned_application[1]);
    close(abandoned_remote[1]);
    close(abandoned_application[0]);
    if (waitpid(relay, &status, 0) != relay) return 14;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 15;
    if (recv(abandoned_remote[0], &byte, 1, 0) != 0) return 16;
    close(abandoned_remote[0]);
    return 0;
}
