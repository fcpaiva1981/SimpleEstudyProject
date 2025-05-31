#include <libssh/libssh.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
    ssh_session session;
    ssh_channel channel;
    int rc;


    session = ssh_new();
    if (session == NULL) {
        std::cerr << "Error creating SSH session: " << ssh_get_error(session) << std::endl;
        return 1;
    }

    std::string hostname = "your_ssh_server_ip_or_hostname";
    std::string username = "your_username";
    std::string password = "your_password";
    int port;

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, username.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, port);


    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        std::cerr << "Error connecting to host " << hostname << ": " << ssh_get_error(session) << std::endl;
        ssh_free(session);
        return 1;
    }



    rc = ssh_userauth_password(session, NULL, password.c_str());
    if (rc != SSH_OK) {
        std::cerr << "Error authenticating with password: " << ssh_get_error(session) << std::endl;

        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }

    std::cout << "Authentication successful!" << std::endl;

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        std::cerr << "Error creating SSH channel: " << ssh_get_error(session) << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        std::cerr << "Error opening SSH channel session: " << ssh_get_error(session) << std::endl;
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }


    std::string command = "ls -l";
    rc = ssh_channel_request_exec(channel, command.c_str());
    if (rc != SSH_OK) {
        std::cerr << "Error executing command '" << command << "': " << ssh_get_error(session) << std::endl;
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }

    char buffer[256];
    int nbytes;
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        std::cout.write(buffer, nbytes);
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    std::cout << "SSH client finished." << std::endl;

    return 0;
}