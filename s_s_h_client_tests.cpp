#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <libssh/libssh.h>


class MockSSHSession {
public:
    MOCK_METHOD(ssh_session, ssh_new, (), ());
    MOCK_METHOD(int, ssh_options_set, (ssh_session session, enum ssh_options_e type, const void* value), ());
    MOCK_METHOD(int, ssh_connect, (ssh_session session), ());
    MOCK_METHOD(int, ssh_userauth_password, (ssh_session session, const char* username, const char* password), ());
    MOCK_METHOD(void, ssh_disconnect, (ssh_session session), ());
    MOCK_METHOD(void, ssh_free, (ssh_session session), ());
};


class SSHClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        session = ssh_new();
    }

    void TearDown() override {
        if (session != nullptr) {
            ssh_free(session);
        }
    }

    ssh_session session;
    MockSSHSession mockSSH;
};


TEST_F(SSHClientTest, CreateSessionSuccess) {
    ASSERT_NE(session, nullptr);
}


TEST_F(SSHClientTest, ConnectionSuccess) {
    std::string hostname = "test_host";
    std::string username = "test_user";
    int port = 22;

    EXPECT_CALL(mockSSH, ssh_options_set(session, SSH_OPTIONS_HOST, testing::_))
        .WillOnce(testing::Return(SSH_OK));
    EXPECT_CALL(mockSSH, ssh_options_set(session, SSH_OPTIONS_USER, testing::_))
        .WillOnce(testing::Return(SSH_OK));
    EXPECT_CALL(mockSSH, ssh_options_set(session, SSH_OPTIONS_PORT, testing::_))
        .WillOnce(testing::Return(SSH_OK));
    EXPECT_CALL(mockSSH, ssh_connect(session))
        .WillOnce(testing::Return(SSH_OK));


    ASSERT_EQ(ssh_options_set(session, SSH_OPTIONS_HOST, hostname.c_str()), SSH_OK);
    ASSERT_EQ(ssh_options_set(session, SSH_OPTIONS_USER, username.c_str()), SSH_OK);
    ASSERT_EQ(ssh_options_set(session, SSH_OPTIONS_PORT, &port), SSH_OK);
    ASSERT_EQ(ssh_connect(session), SSH_OK);
}


TEST_F(SSHClientTest, AuthenticationSuccess) {
    std::string password = "test_password";

    EXPECT_CALL(mockSSH, ssh_userauth_password(session, nullptr, testing::_))
        .WillOnce(testing::Return(SSH_OK));

    ASSERT_EQ(ssh_userauth_password(session, nullptr, password.c_str()), SSH_OK);
}


TEST_F(SSHClientTest, ChannelOperationsSuccess) {
    ssh_channel channel = ssh_channel_new(session);
    ASSERT_NE(channel, nullptr);

    ASSERT_EQ(ssh_channel_open_session(channel), SSH_OK);

    std::string command = "ls -l";
    ASSERT_EQ(ssh_channel_request_exec(channel, command.c_str()), SSH_OK);


    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}


TEST_F(SSHClientTest, ConnectionFailure) {
    EXPECT_CALL(mockSSH, ssh_connect(session))
        .WillOnce(testing::Return(SSH_ERROR));

    ASSERT_EQ(ssh_connect(session), SSH_ERROR);
}


TEST_F(SSHClientTest, AuthenticationFailure) {
    std::string password = "wrong_password";

    EXPECT_CALL(mockSSH, ssh_userauth_password(session, nullptr, testing::_))
        .WillOnce(testing::Return(SSH_ERROR));

    ASSERT_EQ(ssh_userauth_password(session, nullptr, password.c_str()), SSH_ERROR);
}