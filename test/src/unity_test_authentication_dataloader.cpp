#include <gtest/gtest.h>

#include "AuthenticationDataLoader.h"
#include "InitializationAuthenticationFile.h"
#include "LoadAuthenticationStatusFile.h"
#include "TFTPServer.h"
#include "TFTPClient.h"
#include "ISerializableAuthentication.h"

#include <thread>
#include <list>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>

#define LOCALHOST "127.0.0.1"

#define DELTA_TIME 2 // seconds

#define TARGET_HARDWARE_ID "HNPFMS"
#define TARGET_HARDWARE_POSITION "L"
#define TARGET_HARDWARE_IP LOCALHOST

#define TFTP_TARGETHARDWARE_SERVER_PORT 28132
#define TFTP_DATALOADER_SERVER_PORT 45426

class AuthenticationDataLoaderTest : public ::testing::Test
{
protected:
    AuthenticationDataLoaderTest()
    {
        authenticationDataLoader =
            new AuthenticationDataLoader(TARGET_HARDWARE_ID,
                                          TARGET_HARDWARE_POSITION,
                                          TARGET_HARDWARE_IP);
        tftpTargetHardwareServer = new TFTPServer();
        tftpTargetHardwareStatusClient = new TFTPClient();
    }

    ~AuthenticationDataLoaderTest() override
    {
        delete authenticationDataLoader;
        delete tftpTargetHardwareServer;
        delete tftpTargetHardwareStatusClient;
    }
    void SetUp() override
    {

        loadList.push_back(std::make_tuple("certificate/pes.crt", "00000000"));

        ASSERT_EQ(authenticationDataLoader->setLoadList(loadList),
                  AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK);

        ASSERT_EQ(authenticationDataLoader->setTftpTargetHardwareServerPort(
                      TFTP_TARGETHARDWARE_SERVER_PORT),
                  AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK);

        ASSERT_EQ(authenticationDataLoader->setTftpDataLoaderServerPort(
                      TFTP_DATALOADER_SERVER_PORT),
                  AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK);

        ASSERT_EQ(tftpTargetHardwareServer->setPort(
                      TFTP_TARGETHARDWARE_SERVER_PORT),
                  TftpServerOperationResult::TFTP_SERVER_OK);

        ASSERT_EQ(tftpTargetHardwareServer->setTimeout(
                      TFTP_TARGETHARDWARE_SERVER_PORT),
                  TftpServerOperationResult::TFTP_SERVER_OK);

        ASSERT_EQ(tftpTargetHardwareStatusClient->setConnection(LOCALHOST,
                                                                TFTP_DATALOADER_SERVER_PORT),
                  TftpClientOperationResult::TFTP_CLIENT_OK);

        baseFileName = std::string(TARGET_HARDWARE_ID) +
                       std::string("_") +
                       std::string(TARGET_HARDWARE_POSITION);
    }

    void TearDown() override
    {
    }

    AuthenticationDataLoader *authenticationDataLoader;
    TFTPServer *tftpTargetHardwareServer;
    TFTPClient *tftpTargetHardwareStatusClient;
    std::string baseFileName;
    std::vector<AuthenticationLoad> loadList;
};

class TargetServerClienContext
{
public:
    TargetServerClienContext()
    {
        fileBuffer = std::make_shared<std::vector<uint8_t>>();
        loadListReceiveStarted = false;
        waitsReceived = 0;
    }
    ~TargetServerClienContext()
    {
        fileBuffer.reset();
    }
    std::shared_ptr<std::vector<uint8_t>> fileBuffer;
    InitializationAuthenticationFile authenticationFileLAI;
    LoadAuthenticationRequestFile authenticationFileLAR;
    bool loadListReceiveStarted;
    TFTPServer *tftpServer;
    uint16_t authenticationOperationStatusCode;
    uint8_t waitsReceived;
};

TftpServerOperationResult targetHardwareOpenFileCallback(
    ITFTPSection *sectionHandler,
    FILE **fp,
    char *filename,
    char *mode,
    size_t *bufferSize,
    void *context)
{
    if (context != nullptr)
    {
        TargetServerClienContext *targetServerClienContext =
            static_cast<TargetServerClienContext *>(context);

        targetServerClienContext->fileBuffer->clear();
        ISerializableAuthentication *authenticationFile;
        if (strcmp(mode, "r") == 0)
        {
            // SEND LAI FILE
            authenticationFile = dynamic_cast<ISerializableAuthentication *>(&targetServerClienContext->authenticationFileLAI);
            targetServerClienContext->fileBuffer->resize(0);
            authenticationFile->serialize(targetServerClienContext->fileBuffer);

            //            for (auto &it : *targetServerClienContext->fileBuffer) {
            //                printf("%02X (%c) ", it, it);
            //            }
            //            printf("\n");
        }
        else if (strcmp(mode, "w") == 0)
        {
            // RECEIVE LAR FILE
            authenticationFile = dynamic_cast<ISerializableAuthentication *>(&targetServerClienContext->authenticationFileLAR);
            targetServerClienContext->loadListReceiveStarted = true;
            targetServerClienContext->fileBuffer->resize(MAX_CERTIFICATE_BUFFER_SIZE);
        }
        else
        {
            printf("ERROR: Unknown mode %s\n", mode);
            return TftpServerOperationResult::TFTP_SERVER_ERROR;
        }

        (*fp) = fmemopen(targetServerClienContext->fileBuffer->data(),
                         targetServerClienContext->fileBuffer->size(),
                         mode);
        if (bufferSize != NULL)
        {
            *bufferSize = targetServerClienContext->fileBuffer->size();
        }
        if ((*fp) == NULL)
        {
            return TftpServerOperationResult::TFTP_SERVER_ERROR;
        }

        return TftpServerOperationResult::TFTP_SERVER_OK;
    }

    return TftpServerOperationResult::TFTP_SERVER_ERROR;
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderRegisterAuthenticationInitializationResponseCallback)
{
    ASSERT_EQ(authenticationDataLoader->registerAuthenticationInitializationResponseCallback(nullptr, nullptr),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK);
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderRegisterAuthenticationInformationStatusCallback)
{
    ASSERT_EQ(authenticationDataLoader->registerAuthenticationInformationStatusCallback(nullptr, nullptr),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK);
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderRegisterFileNotAvailableCallback)
{
    ASSERT_EQ(authenticationDataLoader->registerCertificateNotAvailableCallback(nullptr, nullptr),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK);
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderLoadEmptyLoadList)
{
    std::vector<AuthenticationLoad> loadList;
    loadList.clear();

    ASSERT_EQ(authenticationDataLoader->setLoadList(loadList),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderOverloadLoadList)
{
    std::vector<AuthenticationLoad> loadList;
    loadList.clear();

    //Max number of certificates = 1
    for (int i = 0; i < 10; i++)
    {
        loadList.push_back(std::make_tuple(std::string("certificate/file") + std::to_string(i),
                                           std::to_string(i)));
    }

    ASSERT_EQ(authenticationDataLoader->setLoadList(loadList),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderTHAuthenticationingInitializationTimeout)
{
    int authentication_operation_time = 0;
    time_t start = time(NULL);
    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);
    time_t end = time(NULL);
    authentication_operation_time = difftime(end, start);

    /*
     * TFTP_TIMEOUT = 2s
     * TFTP_TRIES = 2
     * DLP_TRIES = 2
     * EXPECTED_AUTHENTICATION_OPERATION_TIME = 2*(2*2s) = 8s
     */
    int expected_authentication_operation_time = 8;

    // Times may vary depending on the machine, that's why we're using EXPECT
    // instead of ASSERT
    // EXPECT_LE(authentication_operation_time, expected_authentication_operation_time + DELTA_TIME);
    // EXPECT_GE(authentication_operation_time, expected_authentication_operation_time - DELTA_TIME);
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderTHAuthenticationingInitializationRefused)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to refuse connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_DENIED);

    targetServerClienContext.authenticationFileLAI.setStatusDescription(
        "Operation refused by the target hardware");

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);

    tftpTargetHardwareServer->stopListening();
    serverThread.join();
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderLoadAuthenticationStatusTimeout)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    fprintf(stdout,
            "This test will take about 13 seconds to complete, please wait...\n");

    int authentication_operation_time = 0;
    time_t start = time(NULL);
    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);
    time_t end = time(NULL);
    authentication_operation_time = difftime(end, start);

    // Times may vary depending on the machine, that's why we're using EXPECT
    // instead of ASSERT
    // EXPECT_LE(authentication_operation_time, DEFAULT__DLP_TIMEOUT + DELTA_TIME);
    // EXPECT_GE(authentication_operation_time, DEFAULT__DLP_TIMEOUT - DELTA_TIME);

    tftpTargetHardwareServer->stopListening();
    serverThread.join();
}

TftpServerOperationResult
AuthenticationDataLoaderLoadAuthenticationRequestTimeout_TargetHardwareSectionFinished(
    ITFTPSection *sectionHandler, void *context)
{
    if (context != nullptr)
    {
        TargetServerClienContext *targetServerClienContext =
            static_cast<TargetServerClienContext *>(context);
        targetServerClienContext->tftpServer->stopListening();
    }
    return TftpServerOperationResult::TFTP_SERVER_OK;
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderLoadAuthenticationRequestTimeout)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Save TargetHardware server instance to stop listening as soon as
    // the first section is finished
    targetServerClienContext.tftpServer = tftpTargetHardwareServer;

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    tftpTargetHardwareServer->registerSectionFinishedCallback(
        AuthenticationDataLoaderLoadAuthenticationRequestTimeout_TargetHardwareSectionFinished,
        &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    // Start TargetHardware client to send status message (heartbeat)
    bool sendHeartBeat = true;
    std::thread targetHardwareStatusThread = std::thread([&]
                                                         {

        // Prepare LAS file with authentication accepted status
        std::string targetHardwareStatusFileName =
                baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(
                targetHardwareStatusFileName,
                AUTHENTICATION_VERSION);

        loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(
                STATUS_AUTHENTICATION_ACCEPTED);

        // Serialize message
        std::shared_ptr<std::vector<uint8_t>> fileBuffer =
                std::make_shared<std::vector<uint8_t>>();
        loadAuthenticationStatusFile.serialize(fileBuffer);

        // Send heartbeat
        while (sendHeartBeat) {
            FILE *fp = fmemopen(fileBuffer->data(), fileBuffer->size(), "r");
            if (fp != NULL) {
                tftpTargetHardwareStatusClient->sendFile(
                        targetHardwareStatusFileName.c_str(), fp);
                fclose(fp);
            }
            sleep(1);
        } });

    int authentication_operation_time = 0;
    time_t start = time(NULL);
    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);
    time_t end = time(NULL);
    authentication_operation_time = difftime(end, start);

    sendHeartBeat = false;
    targetHardwareStatusThread.join();

    tftpTargetHardwareServer->stopListening();
    serverThread.join();

    /*
     * TFTP_TIMEOUT = 2s
     * TFTP_TRIES = 2
     * DLP_TRIES = 2
     * EXPECTED_AUTHENTICATION_OPERATION_TIME = 2*(2*2s) = 8s
     */
    int expected_authentication_operation_time = 8;

    // Times may vary depending on the machine, that's why we're using EXPECT
    // instead of ASSERT
    // EXPECT_LE(authentication_operation_time, expected_authentication_operation_time + DELTA_TIME);
    // EXPECT_GE(authentication_operation_time, expected_authentication_operation_time - DELTA_TIME);
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderLoadAuthenticationStatusTimeoutAfterLAR)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    // Start TargetHardware client to send status message (heartbeat)
    std::thread targetHardwareStatusThread = std::thread([&]
                                                         {

        // Prepare LAS file with authentication accepted status
        std::string targetHardwareStatusFileName =
                baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(
                targetHardwareStatusFileName,
                AUTHENTICATION_VERSION);

        loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(
                STATUS_AUTHENTICATION_ACCEPTED);

        // Serialize message
        std::shared_ptr<std::vector<uint8_t>> fileBuffer =
                std::make_shared<std::vector<uint8_t>>();
        loadAuthenticationStatusFile.serialize(fileBuffer);

        // Send 1 heartbeat and stop client as soon as the first message is sent
        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_ERROR;
        while (result != TftpClientOperationResult::TFTP_CLIENT_OK) {
            FILE *fp = fmemopen(fileBuffer->data(), fileBuffer->size(), "r");
            if (fp != NULL) {
                result = tftpTargetHardwareStatusClient->sendFile(
                        targetHardwareStatusFileName.c_str(), fp);
                fclose(fp);
            }
            sleep(1);
        } });

    fprintf(stdout,
            "This test will take about 13 seconds to complete, please wait...\n");

    int authentication_operation_time = 0;
    time_t start = time(NULL);
    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);
    time_t end = time(NULL);
    authentication_operation_time = difftime(end, start);

    targetHardwareStatusThread.join();

    tftpTargetHardwareServer->stopListening();
    serverThread.join();

    // Times may vary depending on the machine, that's why we're using EXPECT
    // instead of ASSERT
    // EXPECT_LE(authentication_operation_time, DEFAULT__DLP_TIMEOUT + DELTA_TIME);
    // EXPECT_GE(authentication_operation_time, DEFAULT__DLP_TIMEOUT - DELTA_TIME);
}

TftpServerOperationResult
AuthenticationDataLoaderAuthenticationSuccess_TargetHardwareSectionFinished(
    ITFTPSection *sectionHandler, void *context)
{
    if (context != nullptr)
    {
        TargetServerClienContext *targetServerClienContext =
            static_cast<TargetServerClienContext *>(context);
        if (targetServerClienContext->loadListReceiveStarted)
        {
            targetServerClienContext->authenticationOperationStatusCode =
                STATUS_AUTHENTICATION_IN_PROGRESS;
        }
    }
    return TftpServerOperationResult::TFTP_SERVER_OK;
}

// Thanks to https://stackoverflow.com/a/15119347/4625435
template <typename InputIterator1, typename InputIterator2>
bool range_equal(InputIterator1 first1, InputIterator1 last1,
                 InputIterator2 first2, InputIterator2 last2)
{
    while (first1 != last1 && first2 != last2)
    {
        if (*first1 != *first2)
            return false;
        ++first1;
        ++first2;
    }
    return (first1 == last1) && (first2 == last2);
}

bool compare_files(const std::string &filename1, const std::string &filename2)
{
    std::ifstream file1(filename1);
    std::ifstream file2(filename2);

    std::istreambuf_iterator<char> begin1(file1);
    std::istreambuf_iterator<char> begin2(file2);

    std::istreambuf_iterator<char> end;

    return range_equal(begin1, end, begin2, end);
}
/////////////////////////////////////////////////////////

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderAuthenticationSuccess)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Init LAR file
    targetServerClienContext.authenticationFileLAR = LoadAuthenticationRequestFile(
        baseFileName + LOAD_AUTHENTICATION_REQUEST_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    tftpTargetHardwareServer->registerSectionFinishedCallback(
        AuthenticationDataLoaderAuthenticationSuccess_TargetHardwareSectionFinished,
        &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    // Start TargetHardware client to send status message (heartbeat)
    targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_ACCEPTED;
    bool sendHeartBeat = true;
    std::thread targetHardwareStatusThread = std::thread([&]
                                                         {

        // Prepare LAS file
        std::string targetHardwareStatusFileName =
                baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(
                targetHardwareStatusFileName,
                AUTHENTICATION_VERSION);

        while (sendHeartBeat) {
            // Set status code
            loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(
                    targetServerClienContext.authenticationOperationStatusCode);

            // Serialize message
            std::shared_ptr<std::vector<uint8_t>> fileBuffer =
                    std::make_shared<std::vector<uint8_t>>();
            loadAuthenticationStatusFile.serialize(fileBuffer);

            // Send heartbeat
            FILE *fp = fmemopen(fileBuffer->data(), fileBuffer->size(), "r");
            if (fp != NULL) {
                tftpTargetHardwareStatusClient->sendFile(
                        targetHardwareStatusFileName.c_str(), fp);
                fclose(fp);
            }
            sleep(1);
        } });

    // TargetHardware client to fetch file from DataLoader
    std::thread targetHardwareAuthenticationThread = std::thread([&]
                                                         {

        // Setup connection
        TFTPClient tftpTargetHardwareAuthenticationClient;
        tftpTargetHardwareAuthenticationClient.setConnection(LOCALHOST,
                                                TFTP_DATALOADER_SERVER_PORT);

        // Wait for connection to be accepted and LAR file is received
        while (targetServerClienContext.authenticationOperationStatusCode !=
                    STATUS_AUTHENTICATION_IN_PROGRESS)
        {
            std::this_thread::yield();
        }

        // Deserialize LAR file
        LoadAuthenticationRequestFile loadAuthenticationRequestFile;
        loadAuthenticationRequestFile.deserialize(
                targetServerClienContext.fileBuffer);

        std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> headerFiles;
        loadAuthenticationRequestFile.getHeaderFiles(headerFiles);

        // Fetch files
        std::vector<std::string> authenticationFiles;
        for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator
                it = headerFiles->begin(); it != headerFiles->end(); ++it)
        {
            std::string fileName;
            (*it).getHeaderFileName(fileName);

            FILE *fp = fopen((fileName+"_tw").c_str(), "w");
            if (fp != NULL) {
                ASSERT_EQ(tftpTargetHardwareAuthenticationClient.fetchFile(fileName.c_str(), fp),
                          TftpClientOperationResult::TFTP_CLIENT_OK);
                fclose(fp);
            } else {
                FAIL() << "FAIL TO CREATE HEADER FILE";
            }
        }

        // Complete operation without errors
        targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_COMPLETED; });

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK);

    sendHeartBeat = false;
    targetHardwareStatusThread.join();

    targetHardwareAuthenticationThread.join();

    tftpTargetHardwareServer->stopListening();
    serverThread.join();

    // Check if fetched files are the same as the ones sent by DataLoader
    for (std::vector<AuthenticationLoad>::iterator it = loadList.begin();
         it != loadList.end(); ++it)
    {
        std::string fileName = std::get<LOAD_FILE_NAME_IDX>(*it);
        ASSERT_TRUE(compare_files(fileName, fileName + "_tw"));
    }
}

TftpServerOperationResult
AuthenticationDataLoaderTargetHardwareAbort_TargetHardwareSectionFinished(
    ITFTPSection *sectionHandler, void *context)
{
    if (context != nullptr)
    {
        TargetServerClienContext *targetServerClienContext =
            static_cast<TargetServerClienContext *>(context);

        // Abort operation as soon as the LAR file is received.
        if (targetServerClienContext->loadListReceiveStarted)
        {
            targetServerClienContext->authenticationOperationStatusCode =
                STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE;
        }
    }
    return TftpServerOperationResult::TFTP_SERVER_OK;
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderTargetHardwareAbort)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Init LAR file
    targetServerClienContext.authenticationFileLAR = LoadAuthenticationRequestFile(
        baseFileName + LOAD_AUTHENTICATION_REQUEST_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    tftpTargetHardwareServer->registerSectionFinishedCallback(
        AuthenticationDataLoaderTargetHardwareAbort_TargetHardwareSectionFinished,
        &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    // Start TargetHardware client to send status message (heartbeat)
    targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_ACCEPTED;
    std::thread targetHardwareStatusThread = std::thread([&]
                                                         {

        // Prepare LAS file
        std::string targetHardwareStatusFileName =
                baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(
                targetHardwareStatusFileName,
                AUTHENTICATION_VERSION);

        // Set status description. This will be relevant only when the
        // operation is aborted.
        loadAuthenticationStatusFile.setAuthenticationStatusDescription(
                "Authentication aborted by the TargetHardware");

        // Send heartbeat until the operation is aborted
        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_OK;
        bool abortSent = false;
        while (!abortSent) {
            // Set status code
            loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(
                    targetServerClienContext.authenticationOperationStatusCode);

            // Get status code to confirm if we'll send abort
            uint16_t statusCode;
            loadAuthenticationStatusFile.getAuthenticationOperationStatusCode(statusCode);

            // Serialize message
            std::shared_ptr<std::vector<uint8_t>> fileBuffer =
                    std::make_shared<std::vector<uint8_t>>();
            loadAuthenticationStatusFile.serialize(fileBuffer);

            // Send heartbeat
            FILE *fp = fmemopen(fileBuffer->data(), fileBuffer->size(), "r");
            if (fp != NULL) {
                result = tftpTargetHardwareStatusClient->sendFile(
                            targetHardwareStatusFileName.c_str(), fp);
                fclose(fp);
            }
            sleep(1);

            if ((statusCode == STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE)
                && (result == TftpClientOperationResult::TFTP_CLIENT_OK)) {
                abortSent = true;
            }
        } });

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);

    targetHardwareStatusThread.join();

    tftpTargetHardwareServer->stopListening();
    serverThread.join();
}

TftpClientOperationResult TftpErrorCbk(
    short error_code,
    std::string &error_message,
    void *context)
{
    if (context != nullptr)
    {
        TargetServerClienContext *ctx =
            (TargetServerClienContext *)context;

        if (error_code == 0)
        {
            std::string abortPrefix = std::string(AUTHENTICATION_ABORT_MSG_PREFIX) +
                                      std::string(AUTHENTICATION_ERROR_MSG_DELIMITER);
            size_t pos = error_message.find(abortPrefix);
            if (pos != std::string::npos)
            {
                pos = error_message.find(AUTHENTICATION_ERROR_MSG_DELIMITER);
                std::string abortCode = error_message.substr(
                    pos + 1, error_message.length());

                ctx->authenticationOperationStatusCode = std::stoul(abortCode,
                                                            nullptr, 16);

                // std::stringstream ss;
                // ss << std::hex << abortCode;
                // ss >> ctx->authenticationOperationStatusCode;
                return TftpClientOperationResult::TFTP_CLIENT_OK;
            }

            std::string waitPrefix = std::string(AUTHENTICATION_WAIT_MSG_PREFIX) +
                                     std::string(AUTHENTICATION_ERROR_MSG_DELIMITER);
            pos = error_message.find(waitPrefix);
            if (pos != std::string::npos)
            {
                pos = error_message.find(AUTHENTICATION_ERROR_MSG_DELIMITER);
                std::string waitSeconds = error_message.substr(
                    pos + 1, error_message.length());

                ctx->waitsReceived += std::stoi(waitSeconds);

                return TftpClientOperationResult::TFTP_CLIENT_OK;
            }
        }
    }
    return TftpClientOperationResult::TFTP_CLIENT_ERROR;
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderDataLoaderAbort)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Init LAR file
    targetServerClienContext.authenticationFileLAR = LoadAuthenticationRequestFile(
        baseFileName + LOAD_AUTHENTICATION_REQUEST_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    tftpTargetHardwareServer->registerSectionFinishedCallback(
        AuthenticationDataLoaderAuthenticationSuccess_TargetHardwareSectionFinished,
        &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    bool authenticationAborted = false;

    // TargetHardware client to fetch file from DataLoader
    targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_ACCEPTED;
    std::thread targetHardwareAuthenticationThread = std::thread([&]
                                                         {

        // Setup connection
        TFTPClient tftpTargetHardwareAuthenticationClient;
        tftpTargetHardwareAuthenticationClient.setConnection(LOCALHOST,
                                                TFTP_DATALOADER_SERVER_PORT);
        // tftpTargetHardwareAuthenticationClient.registerTftpErrorCallback(
        //                                     TftpErrorCbk,
        //                                     &targetServerClienContext);

        // Wait for connection to be accepted and LAR file is received
        while (targetServerClienContext.authenticationOperationStatusCode !=
                    STATUS_AUTHENTICATION_IN_PROGRESS)
        {
            std::this_thread::yield();
        }

        // Deserialize LAR file
        LoadAuthenticationRequestFile loadAuthenticationRequestFile;
        loadAuthenticationRequestFile.deserialize(
                targetServerClienContext.fileBuffer);

        std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> headerFiles;
        loadAuthenticationRequestFile.getHeaderFiles(headerFiles);

        // Fetch files
        std::vector<std::string> authenticationFiles;
        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_OK;
        for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator
                it = headerFiles->begin(); it != headerFiles->end(); ++it)
        {
            // Make fetch process slow so we can abort the process
            sleep(5);

            std::string fileName;
            (*it).getHeaderFileName(fileName);

            if (authenticationAborted) 
            {
                break;
            }

            FILE *fp = fopen((fileName+"_tw").c_str(), "w");
            if (fp != NULL) {
                result = tftpTargetHardwareAuthenticationClient.fetchFile(fileName.c_str(), fp);
                fclose(fp);
            } else {
                FAIL() << "FAIL TO CREATE HEADER FILE";
            }
        }

        if (!authenticationAborted && 
            result == TftpClientOperationResult::TFTP_CLIENT_OK) 
        {
            targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_COMPLETED;
        } });

    // Start TargetHardware client to send status message (heartbeat)
    std::thread targetHardwareStatusThread = std::thread([&]
                                                         {

        tftpTargetHardwareStatusClient->registerTftpErrorCallback(
                                            TftpErrorCbk,
                                            &targetServerClienContext);

        // Prepare LAS file
        std::string targetHardwareStatusFileName =
                baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(
                targetHardwareStatusFileName,
                AUTHENTICATION_VERSION);

        // Send heartbeat until the operation is aborted
        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_OK;
        bool abortSent = false;
        while (!abortSent) {
            // Set status code
            loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(
                    targetServerClienContext.authenticationOperationStatusCode);

            // Get status code to confirm if we'll send abort
            uint16_t statusCode;
            loadAuthenticationStatusFile.getAuthenticationOperationStatusCode(
                                                    statusCode);

            if (statusCode == STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_DL_REQUEST) 
            {
                authenticationAborted = true;
                if (targetHardwareAuthenticationThread.joinable()) {
                    targetHardwareAuthenticationThread.join();
                }                
            }

            // Serialize message
            std::shared_ptr<std::vector<uint8_t>> fileBuffer =
                    std::make_shared<std::vector<uint8_t>>();
            loadAuthenticationStatusFile.serialize(fileBuffer);

            // Send heartbeat
            FILE *fp = fmemopen(fileBuffer->data(), fileBuffer->size(), "r");
            if (fp != NULL) {
                result = tftpTargetHardwareStatusClient->sendFile(
                            targetHardwareStatusFileName.c_str(), fp);
                fclose(fp);
            }

            sleep(1);

            if ((statusCode == STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_DL_REQUEST)
                && (result == TftpClientOperationResult::TFTP_CLIENT_OK)) {
                abortSent = true;
            }
        } });

    // Authentication is a blocking call, so we need to abord from another thread
    std::thread authenticationAbortThread = std::thread([&]
                                                {
        // Wait for authentication to start
        while (targetServerClienContext.authenticationOperationStatusCode !=
                    STATUS_AUTHENTICATION_IN_PROGRESS)
        {
            std::this_thread::yield();
        }
        ASSERT_EQ(authenticationDataLoader->abort(
                    AUTHENTICATION_ABORT_SOURCE_DATALOADER), 
                  AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK); });

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);

    ASSERT_EQ(targetServerClienContext.authenticationOperationStatusCode,
              STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_DL_REQUEST);

    authenticationAbortThread.join();
    targetHardwareStatusThread.join();

    tftpTargetHardwareServer->stopListening();
    serverThread.join();
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderOperatorAbort)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Init LAR file
    targetServerClienContext.authenticationFileLAR = LoadAuthenticationRequestFile(
        baseFileName + LOAD_AUTHENTICATION_REQUEST_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    tftpTargetHardwareServer->registerSectionFinishedCallback(
        AuthenticationDataLoaderAuthenticationSuccess_TargetHardwareSectionFinished,
        &targetServerClienContext);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    bool authenticationAborted = false;

    // TargetHardware client to fetch file from DataLoader
    targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_ACCEPTED;
    std::thread targetHardwareAuthenticationThread = std::thread([&]
                                                         {

        // Setup connection
        TFTPClient tftpTargetHardwareAuthenticationClient;
        tftpTargetHardwareAuthenticationClient.setConnection(LOCALHOST,
                                                TFTP_DATALOADER_SERVER_PORT);
        // tftpTargetHardwareAuthenticationClient.registerTftpErrorCallback(
        //                                     TftpErrorCbk,
        //                                     &targetServerClienContext);

        // Wait for connection to be accepted and LAR file is received
        while (targetServerClienContext.authenticationOperationStatusCode !=
                    STATUS_AUTHENTICATION_IN_PROGRESS)
        {
            std::this_thread::yield();
        }

        // Deserialize LAR file
        LoadAuthenticationRequestFile loadAuthenticationRequestFile;
        loadAuthenticationRequestFile.deserialize(
                targetServerClienContext.fileBuffer);

        std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> headerFiles;
        loadAuthenticationRequestFile.getHeaderFiles(headerFiles);

        // Fetch files
        std::vector<std::string> authenticationFiles;
        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_OK;
        for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator
                it = headerFiles->begin(); it != headerFiles->end(); ++it)
        {
            // Make fetch process slow so we can abort the process
            sleep(5);

            std::string fileName;
            (*it).getHeaderFileName(fileName);

            if (authenticationAborted) 
            {
                break;
            }

            FILE *fp = fopen((fileName+"_tw").c_str(), "w");
            if (fp != NULL) {
                result = tftpTargetHardwareAuthenticationClient.fetchFile(fileName.c_str(), fp);
                fclose(fp);
            } else {
                FAIL() << "FAIL TO CREATE HEADER FILE";
            }
        }

        if (!authenticationAborted && 
            result == TftpClientOperationResult::TFTP_CLIENT_OK) 
        {
            targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_COMPLETED;
        } });

    // Start TargetHardware client to send status message (heartbeat)
    std::thread targetHardwareStatusThread = std::thread([&]
                                                         {

        tftpTargetHardwareStatusClient->registerTftpErrorCallback(
                                            TftpErrorCbk,
                                            &targetServerClienContext);
        // Prepare LAS file
        std::string targetHardwareStatusFileName =
                baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(
                targetHardwareStatusFileName,
                AUTHENTICATION_VERSION);

        // Send heartbeat until the operation is aborted
        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_OK;
        bool abortSent = false;
        while (!abortSent) {
            // Set status code
            loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(
                    targetServerClienContext.authenticationOperationStatusCode);

            // Get status code to confirm if we'll send abort
            uint16_t statusCode;
            loadAuthenticationStatusFile.getAuthenticationOperationStatusCode(
                                                    statusCode);

            if (statusCode == STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_OP_REQUEST) 
            {
                authenticationAborted = true;
                if (targetHardwareAuthenticationThread.joinable()) {
                    targetHardwareAuthenticationThread.join();
                }                
            }

            // Serialize message
            std::shared_ptr<std::vector<uint8_t>> fileBuffer =
                    std::make_shared<std::vector<uint8_t>>();
            loadAuthenticationStatusFile.serialize(fileBuffer);

            // Send heartbeat
            FILE *fp = fmemopen(fileBuffer->data(), fileBuffer->size(), "r");
            if (fp != NULL) {
                result = tftpTargetHardwareStatusClient->sendFile(
                            targetHardwareStatusFileName.c_str(), fp);
                fclose(fp);
            }

            sleep(1);

            if ((statusCode == STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_OP_REQUEST)
                && (result == TftpClientOperationResult::TFTP_CLIENT_OK)) {
                abortSent = true;
            }
        } });

    // Authentication is a blocking call, so we need to abord from another thread
    std::thread authenticationAbortThread = std::thread([&]
                                                {
        // Wait for authentication to start
        while (targetServerClienContext.authenticationOperationStatusCode !=
                    STATUS_AUTHENTICATION_IN_PROGRESS)
        {
            std::this_thread::yield();
        }
        ASSERT_EQ(authenticationDataLoader->abort(
                    AUTHENTICATION_ABORT_SOURCE_OPERATOR), 
                  AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK); });

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);

    ASSERT_EQ(targetServerClienContext.authenticationOperationStatusCode,
              STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_OP_REQUEST);

    authenticationAbortThread.join();
    targetHardwareStatusThread.join();

    tftpTargetHardwareServer->stopListening();
    serverThread.join();
}

AuthenticationOperationResult AuthenticationDataLoaderCertificateNotFound_certificateNotAvailableCbk(
    std::string fileName,
    uint16_t *waitTimeS,
    void *context)
{
    *waitTimeS = DEFAULT_WAIT_TIME;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

TEST_F(AuthenticationDataLoaderTest, AuthenticationDataLoaderFileNotFound)
{
    TargetServerClienContext targetServerClienContext;

    // Prepare LAI file to accept connection
    targetServerClienContext.authenticationFileLAI = InitializationAuthenticationFile(
        baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    targetServerClienContext.authenticationFileLAI.setOperationAcceptanceStatusCode(
        OPERATION_IS_ACCEPTED);

    // Init LAR file
    targetServerClienContext.authenticationFileLAR = LoadAuthenticationRequestFile(
        baseFileName + LOAD_AUTHENTICATION_REQUEST_FILE_EXTENSION,
        AUTHENTICATION_VERSION);

    // Override load list
    std::vector<AuthenticationLoad> inexistentLoadList;
    inexistentLoadList.push_back(
        std::make_tuple("certificate/inexistent_pes.crt", "00000000"));
    authenticationDataLoader->setLoadList(inexistentLoadList);

    // Register server callbacks
    tftpTargetHardwareServer->registerOpenFileCallback(
        targetHardwareOpenFileCallback, &targetServerClienContext);

    tftpTargetHardwareServer->registerSectionFinishedCallback(
        AuthenticationDataLoaderAuthenticationSuccess_TargetHardwareSectionFinished,
        &targetServerClienContext);

    authenticationDataLoader->registerCertificateNotAvailableCallback(
        AuthenticationDataLoaderCertificateNotFound_certificateNotAvailableCbk,
        nullptr);

    // Start TargetHardware server
    std::thread serverThread = std::thread([this]
                                           { tftpTargetHardwareServer->startListening(); });

    // Start TargetHardware client to send status message (heartbeat)
    targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_ACCEPTED;
    bool sendHeartBeat = true;
    std::thread targetHardwareStatusThread = std::thread([&]
                                                         {

        // Prepare LAS file
        std::string targetHardwareStatusFileName =
                baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(
                targetHardwareStatusFileName,
                AUTHENTICATION_VERSION);

        while (sendHeartBeat) {
            // Set status code
            loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(
                    targetServerClienContext.authenticationOperationStatusCode);

            // Serialize message
            std::shared_ptr<std::vector<uint8_t>> fileBuffer =
                    std::make_shared<std::vector<uint8_t>>();
            loadAuthenticationStatusFile.serialize(fileBuffer);

            // Send heartbeat
            FILE *fp = fmemopen(fileBuffer->data(), fileBuffer->size(), "r");
            if (fp != NULL) {
                tftpTargetHardwareStatusClient->sendFile(
                        targetHardwareStatusFileName.c_str(), fp);
                fclose(fp);
            }
            sleep(1);
        } });

    // TargetHardware client to fetch file from DataLoader
    std::thread targetHardwareAuthenticationThread = std::thread([&]
                                                         {

        // Setup connection
        TFTPClient tftpTargetHardwareAuthenticationClient;
        tftpTargetHardwareAuthenticationClient.setConnection(LOCALHOST,
                                                TFTP_DATALOADER_SERVER_PORT);
        tftpTargetHardwareAuthenticationClient.registerTftpErrorCallback(
                                            TftpErrorCbk,
                                            &targetServerClienContext);

        // Wait for connection to be accepted and LAR file is received
        while (targetServerClienContext.authenticationOperationStatusCode !=
                    STATUS_AUTHENTICATION_IN_PROGRESS)
        {
            std::this_thread::yield();
        }

        // Deserialize LAR file
        LoadAuthenticationRequestFile loadAuthenticationRequestFile;
        loadAuthenticationRequestFile.deserialize(
                targetServerClienContext.fileBuffer);

        std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> headerFiles;
        loadAuthenticationRequestFile.getHeaderFiles(headerFiles);

        // Fetch files
        targetServerClienContext.waitsReceived = 0;
        std::vector<std::string> authenticationFiles;
        for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator
                it = headerFiles->begin(); it != headerFiles->end(); ++it)
        {
            std::string fileName;
            (*it).getHeaderFileName(fileName);

            FILE *fp = fopen((fileName+"_tw").c_str(), "w");
            if (fp != NULL) {
                ASSERT_EQ(tftpTargetHardwareAuthenticationClient.fetchFile(fileName.c_str(), fp),
                          TftpClientOperationResult::TFTP_CLIENT_ERROR);
                fclose(fp);
            } else {
                FAIL() << "FAIL TO CREATE HEADER FILE";
            }
        }

        // Abort operation
        targetServerClienContext.authenticationOperationStatusCode = STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE; });

    ASSERT_EQ(authenticationDataLoader->authenticate(),
              AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR);

    sendHeartBeat = false;
    targetHardwareStatusThread.join();

    targetHardwareAuthenticationThread.join();

    tftpTargetHardwareServer->stopListening();
    serverThread.join();

    ASSERT_EQ(targetServerClienContext.authenticationOperationStatusCode,
              STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE);

    ASSERT_EQ(targetServerClienContext.waitsReceived,
              inexistentLoadList.size() * DEFAULT_WAIT_TIME);
}