#ifndef AUTHENTICATIONDATALOADER_H
#define AUTHENTICATIONDATALOADER_H

#include <string>
#include <condition_variable>
#include <mutex>
#include <unordered_map>
#include <tuple>

#include "TFTPServer.h"
#include "AuthenticationBase.h"

#define DEFAULT_WAIT_TIME 1 // second

/**
 * @brief This data type will be used to store a single load. The stored
 *        format must be <FileName, PartNumber>
 */
#define LOAD_FILE_NAME_IDX 0
#define LOAD_PART_NUMBER_IDX 1
typedef std::tuple<std::string, std::string> AuthenticationLoad;

class LoadAuthenticationRequestFile;

/**
 * @brief Callback for authentication initialization operation response.
 *
 * //TODO: document the JSON format.
 *
 * @param[in] authenticationInitializationResponseJson JSON with initialization response.
 * @param[in] context the user context.
 *
 * @return AUTHENTICATION_OPERATION_OK if success.
 * @return AUTHENTICATION_OPERATION_ERROR otherwise.
 */
typedef AuthenticationOperationResult (*authenticationInitializationResponseCallback)(
    std::string authenticationInitializationResponseJson,
    void *context);

/**
 * @brief Callback to prepare files for authentication operation. Use this callback
 *       to cypher the files.
 *
 * @param[in] fileName file name to be prepared.
 * @param[in] fp File pointer to the file. You can manipulate this pointer to
 *               point to a new file if this is necessary.
 * @param[out] bufferSize Size of the buffer if file is loaded in memory. If
 *                       file is not loaded in memory, this value must be 0.
 * @param[in] context the user context.
 *
 * @return AUTHENTICATION_OPERATION_OK if success.
 * @return AUTHENTICATION_OPERATION_ERROR otherwise.
 */
typedef AuthenticationOperationResult (*loadPrepareCallback)(
    std::string fileName,
    FILE **fp,
    size_t *bufferSize,
    void *context);

/**
 * @brief Callback for authentication progress report.
 *
 * //TODO: document the JSON format.
 *
 * @param[in] authenticationInformationStatusJson JSON with authentication information status.
 * @param[in] context the user context.
 *
 * @return AUTHENTICATION_OPERATION_OK if success.
 * @return AUTHENTICATION_OPERATION_ERROR otherwise.
 */
typedef AuthenticationOperationResult (*authenticationInformationStatusCallback)(
    std::string authenticationInformationStatusJson,
    void *context);

/**
 * @brief Callback for certificate not available.
 *
 * //TODO: document the JSON format.
 *
 * @param[in] fileName the name of the certificate file
 * @param[out] waitTimeS time to wait in seconds before next call.
 * @param[in] context the user context.
 *
 * @return AUTHENTICATION_OPERATION_OK if success.
 * @return AUTHENTICATION_OPERATION_ERROR otherwise.
 */
typedef AuthenticationOperationResult (*certificateNotAvailableCallback)(
    std::string fileName,
    uint16_t *waitTimeS,
    void *context);

/**
 * @brief Class to handle authentication operation on the DataLoader side.
 */
class AuthenticationDataLoader : public AuthenticationBase
{
public:
    AuthenticationDataLoader(std::string targetHardwareId = "",
                             std::string targetHardwarePosition = "",
                             std::string targetHardwareIp = "");
    virtual ~AuthenticationDataLoader();

    /**
     * @brief Set TargetHardware ID. This is the ID of the TargetHardware where the
     *        load will be authenticationed. You can get the TargetHardware's ID from the
     *        find operation.
     *
     * @param[in] targetHardwareId the TargetHardware ID.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult setTargetHardwareId(std::string &targetHardwareId);

    /**
     * @brief Set TargetHardware position. This is the position of the TargetHardware
     *        where the load will be authenticationed. You can get the TargetHardware's
     *        position from the find operation.
     *
     * @param[in] targetHardwarePosition the TargetHardware position.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult setTargetHardwarePosition(
        std::string &targetHardwarePosition);

    /**
     * @brief Set TargetHardware IP. This is the IP of the TargetHardware
     *        where the load will be authenticationed. You can get the TargetHardware's
     *        IP from the find operation.
     *
     * @param[in] targetHardwareIp the TargetHardware IP.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult setTargetHardwareIp(std::string &targetHardwareIp);

    /**
     * @brief Set DataLoader server PORT. This is the port where the DataLoader
     *       will listen for the authentication operation.
     *
     * @param[in] port the port number.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult setTftpDataLoaderServerPort(uint16_t port);

    /**
     * @brief Set TargetHardware server PORT. This is the port to connect to the
     *       TargetHardware.
     *
     * @param[in] port the port number.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult setTftpTargetHardwareServerPort(uint16_t port);

    /**
     * @brief Set load list.
     *
     * @param[in] loadList the load list.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult setLoadList(std::vector<AuthenticationLoad> loadList);

    /**
     * @brief Start authentication operation. This method must called by the dataloader
     * to start the authentication to the target hardware.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult authenticate();

    /**
     * Register a callback for authentication initialization response.
     *
     * @param[in] callback the callback.
     * @param[in] context the user context.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult registerAuthenticationInitializationResponseCallback(
        authenticationInitializationResponseCallback callback,
        void *context);

    /**
     * Register a callback for authentication information status.
     *
     * @param[in] callback the callback.
     * @param[in] context the user context.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult registerAuthenticationInformationStatusCallback(
        authenticationInformationStatusCallback callback,
        void *context);

    /**
     * Register a callback for load preparation.
     *
     * @param[in] callback the callback.
     * @param[in] context the user context.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult registerAuthenticationLoadPrepare(
        loadPrepareCallback callback,
        void *context);

    /**
     * Register a callback for certificate not available.
     *
     * @param[in] callback the callback.
     * @param[in] context the user context.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    AuthenticationOperationResult registerCertificateNotAvailableCallback(
        certificateNotAvailableCallback callback,
        void *context);

    AuthenticationOperationResult abort(uint16_t abortSource) override;

private:
    class TargetClient
    {
    public:
        TargetClient(TftpSectionId clientId);
        ~TargetClient();

        AuthenticationOperationResult getClientId(TftpSectionId &clientId);
        AuthenticationOperationResult getClientFileBufferReference(FILE **fp);
        AuthenticationOperationResult getClientBufferReference(char **buffer);
        AuthenticationOperationResult setFileName(std::string fileName);
        AuthenticationOperationResult getFileName(std::string &fileName);
        AuthenticationOperationResult setSectionFinished();
        AuthenticationOperationResult isSectionFinished(bool &sectionFinished);
        AuthenticationOperationResult hasDataToProcess(bool &hasDataToProcess);

    private:
        TftpSectionId clientId;
        std::string fileName;
        char *clientFileBuffer;
        bool sectionFinished;
    };

    AuthenticationOperationResult initTFTP();
    AuthenticationOperationResult initAuthenticationFiles(
        LoadAuthenticationRequestFile &loadAuthenticationRequestFile);

    static TftpServerOperationResult targetHardwareSectionStarted(
        ITFTPSection *sectionHandler, void *context);
    static TftpServerOperationResult targetHardwareSectionFinished(
        ITFTPSection *sectionHandler, void *context);
    static TftpServerOperationResult targetHardwareOpenFileRequest(
        ITFTPSection *sectionHandler, FILE **fp, char *filename,
        char *mode, size_t *bufferSize, void *context);
    static TftpServerOperationResult targetHardwareCloseFileRequest(
        ITFTPSection *sectionHandler, FILE *fp, void *context);

    std::mutex targetClientsMutex;
    std::unordered_map<TftpSectionId, std::shared_ptr<TargetClient>> targetClients;
    std::condition_variable clientProcessorCV;
    std::mutex clientProcessorMutex;
    AuthenticationOperationResult clientProcessor();
    AuthenticationOperationResult processFile(std::string fileName, char *buffer);
    AuthenticationOperationResult processLoadAuthenticationStatusFile(char *buffer);

    bool toggleAbortSend;
    AuthenticationOperationResult abortTargetRequest(uint16_t abortSource,
                                                     ITFTPSection *sectionHandler,
                                                     char *filename, char *mode);
    uint16_t abortSource;

    std::string targetHardwareId;
    std::string targetHardwarePosition;
    std::string targetHardwareIp;
    std::vector<AuthenticationLoad> loadList;

    void *_authenticationInitializationResponseContext;
    authenticationInitializationResponseCallback _authenticationInitializationResponseCallback;

    void *_authenticationInformationStatusContext;
    authenticationInformationStatusCallback _authenticationInformationStatusCallback;

    void *_fileNotAvailableContext;
    certificateNotAvailableCallback _certificateNotAvailableCallback;

    void *_loadPrepareContext;
    loadPrepareCallback _loadPrepareCallback;

    uint16_t tftpTargetHardwareServerPort;
    uint16_t tftpDataLoaderServerPort;
    std::unique_ptr<ITFTPServer> tftpServer;

    std::condition_variable filesProcessedCV;
    std::mutex filesProcessedMutex;

    std::condition_variable endAuthenticationCV;
    std::mutex endAuthenticationMutex;

    bool authenticationInitializationAccepted;
    bool authenticationCompleted;
    bool endAuthentication;
};

#endif // AUTHENTICATIONDATALOADER_H
