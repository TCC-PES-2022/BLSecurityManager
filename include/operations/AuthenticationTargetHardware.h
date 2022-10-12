#ifndef AUTHENTICATIONTARGETHARDWARE_H
#define AUTHENTICATIONTARGETHARDWARE_H

#include "AuthenticationBase.h"
#include "LoadAuthenticationStatusFile.h"
#include "INotifierAuthentication.h"

#include <thread>
#include <mutex>
#include <condition_variable>

// TODO: Create an interface for generic FSM
enum class AuthenticationTargetHardwareState
{
    CREATED,
    ACCEPTED,
    DENIED,
    IN_PROGRESS,
    IN_PROGRESS_WITH_DESCRIPTION,
    ABORTED_BY_TARGET,
    ABORTED_BY_DATALOADER,
    ABORTED_BY_OPERATOR,
    COMPLETED,
    ERROR,
    FINISHED,
};

/*
 * @brief Callback to check received certificate
 *
 * @param[in] fileBuffer Received certificate content. If a cryptographic key 
 *             was generated, the content is encrypted with the key.
 * @param[in] fileSize Received file size
 * @param[in] checkReport report description of operation
 * @param[in] context user context
 *
 * @return AUTHENTICATION_OPERATION_OK if success.
 * @return AUTHENTICATION_OPERATION_ERROR otherwise.
 */
typedef AuthenticationOperationResult (*checkCertificateCallback)(
    unsigned char *fileBuffer,
    size_t fileSize,
    std::string &checkDescription,
    void *context);

/*
 * @brief Generate criptographic key callback. Use this callback to generate a
 *        criptographic key to be used in the authentication process.
 *
 * @param[in] baseFileName base file name (THW_ID_POS)
 * @param[out] key criptographic key
 * @param[in] context user context
 *
 * @return AUTHENTICATION_OPERATION_OK if success.
 * @return AUTHENTICATION_OPERATION_ERROR otherwise.
 */
typedef AuthenticationOperationResult (*generateCryptographicKeyCallback)(
    std::string baseFileName,
    std::vector<uint8_t> &key,
    void *context);

/*
 * @brief Callback to check authentication operation. This callback is called when all
 *        files have been received, so the TargetHardware can perform one
 *       last check before sending OK to DataLoader.
 *
 * @param[in] checkReport report description of operation
 * @param[in] context user context
 *
 * @return AUTHENTICATION_OPERATION_OK if success.
 * @return AUTHENTICATION_OPERATION_ERROR otherwise.
 */
// typedef AuthenticationOperationResult (*transmissionCheckCallback)(
//     std::string &checkDescription,
//     void *context);

/**
 * @brief Class to handle authentication operation on the TargetHardware side.
 */
class AuthenticationTargetHardware : public AuthenticationBase, public INotifierAuthentication
{
public:
    AuthenticationTargetHardware(std::string dataLoaderIp,
                                 int dataLoaderPort =
                                     DEFAULT_AUTHENTICATION_TFTP_PORT);
    virtual ~AuthenticationTargetHardware();

    /**
     * @brief Register a callback to check if the files are valid.
     *
     * @param[in] callback the callback to check if the files are valid.
     * @param[in] context the context to be passed to the callback.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult registerCheckCertificateCallback(
        checkCertificateCallback callback,
        void *context);

    /**
     * @brief Register a callback to generate a criptographic key.
     *
     * @param[in] callback the callback to generate a criptographic key.
     * @param[in] context the context to be passed to the callback.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult registerGenerateCryptographicKeyCallback(
        generateCryptographicKeyCallback callback,
        void *context);

    /**
     * @brief Register a callback for a final transmission check.
     *
     * @param[in] callback the callback to check if transmission is valid.
     * @param[in] context the context to be passed to the callback.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    // AuthenticationOperationResult registerTransmissionCheckCallback(
    //     transmissionCheckCallback callback,
    //     void *context);

    /**
     * @brief Authentication request from the dataloader.
     *
     * @param[out] fp file descriptor to the <THW_ID_POS>.LAI for read
     * ([Authenticationing_Initialization_Response])
     * @param[out] bufferSize size of the buffer containing the file.
     * @param[in] fileName name of the LAI file.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult loadAuthenticationInitialization(
        FILE **fp, size_t *bufferSize, std::string &fileName);

    /**
     * @brief Load list write request from the dataloader.
     *
     * @param[out] fp file descriptor to the <THW_ID_POS>.LAR for write
     * ([Load_List])
     * @param[out] bufferSize size of the buffer containing the file.
     * @param[in] fileName name of the LAR file.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult loadAuthenticationRequest(
        FILE **fp, size_t *bufferSize, std::string &fileName);

    /**
     * @brief Get current state of the authentication operation.
     *
     * @param[out] state current state of the authentication operation.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult getState(AuthenticationTargetHardwareState &state);

    NotifierAuthenticationOperationResult notify(NotifierAuthenticationEventType event) override;

    AuthenticationOperationResult abort(uint16_t abortSource) override;

private:
    std::string dataLoaderIp;
    int dataLoaderPort;

    uint16_t authenticationOperationStatusCode;
    uint32_t loadListRatio;

    bool authenticationAborted;
    std::mutex abortedMutex;

    checkCertificateCallback _checkCertificateCallback;
    void *_checkCertificateContext;
    // transmissionCheckCallback _transmissionCheckCallback;
    // void *_transmissionCheckContext;
    generateCryptographicKeyCallback _generateCryptographicKeyCallback;
    void *_generateCryptographicKeyContext;

    std::string baseFileName;
    std::shared_ptr<std::vector<uint8_t>> loadAuthenticationInitializationFileBuffer;
    std::shared_ptr<std::vector<uint8_t>> loadAuthenticationRequestFileBuffer;

    std::shared_ptr<std::vector<LoadAuthenticationStatusHeaderFile>> statusHeaderFiles;

    AuthenticationOperationResult checkAuthenticationConditions();

    // Current state holds the last state successfully sent to the dataloader
    AuthenticationTargetHardwareState currentState;

    // Next state holds the next state to be sent to the dataloader (except for
    // created, error and finished, those are internal states)
    AuthenticationTargetHardwareState nextState;

    bool runMainThread;
    bool runStatusThread;
    bool runAuthenticationThread;
    AuthenticationOperationResult mainThread();
    std::thread *_mainThread;
    std::mutex _mainThreadMutex;
    std::condition_variable _mainThreadCV;

    std::string authenticationStatusDescription;
    AuthenticationOperationResult statusThread();

    static TftpClientOperationResult tftpAuthenticationErrorCbk(short error_code,
                                                                std::string &error_message,
                                                                void *context);
    AuthenticationOperationResult authenticationThread();
    uint16_t authenticationWaitTime;
};

#endif // AUTHENTICATIONTARGETHARDWARE_H
