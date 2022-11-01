#include "AuthenticationDataLoader.h"
#include "InitializationAuthenticationFile.h"
#include "LoadAuthenticationRequestFile.h"
#include "LoadAuthenticationStatusFile.h"

#include <thread>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <sstream>

AuthenticationDataLoader::AuthenticationDataLoader(std::string targetHardwareId,
                                                   std::string targetHardwarePosition,
                                                   std::string targetHardwareIp)
{
    this->targetHardwareId = targetHardwareId;
    this->targetHardwarePosition = targetHardwarePosition;
    this->targetHardwareIp = targetHardwareIp;
    this->loadList.clear();

    tftpClient = nullptr;
    tftpServer = nullptr;

    tftpDataLoaderServerPort = DEFAULT_AUTHENTICATION_TFTP_PORT;
    tftpTargetHardwareServerPort = DEFAULT_AUTHENTICATION_TFTP_PORT;

    toggleAbortSend = false;

    _authenticationInitializationResponseContext = NULL;
    _authenticationInitializationResponseCallback = nullptr;
    _authenticationInformationStatusContext = NULL;
    _authenticationInformationStatusCallback = nullptr;
    _fileNotAvailableContext = NULL;
    _certificateNotAvailableCallback = nullptr;
    _loadPrepareContext = NULL;
    _loadPrepareCallback = nullptr;
}

AuthenticationDataLoader::~AuthenticationDataLoader()
{
    loadList.clear();

    if (tftpClient != nullptr)
    {
        tftpClient.reset();
        tftpClient = nullptr;
    }

    if (tftpServer != nullptr)
    {
        tftpServer.reset();
        tftpServer = nullptr;
    }
}

AuthenticationOperationResult
AuthenticationDataLoader::registerAuthenticationInitializationResponseCallback(
    authenticationInitializationResponseCallback callback,
    void *context)
{
    _authenticationInitializationResponseCallback = callback;
    _authenticationInitializationResponseContext = context;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult
AuthenticationDataLoader::registerAuthenticationInformationStatusCallback(
    authenticationInformationStatusCallback callback,
    void *context)
{
    _authenticationInformationStatusCallback = callback;
    _authenticationInformationStatusContext = context;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult
AuthenticationDataLoader::registerCertificateNotAvailableCallback(
    certificateNotAvailableCallback callback,
    void *context)
{
    _certificateNotAvailableCallback = callback;
    _fileNotAvailableContext = context;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::registerAuthenticationLoadPrepare(
    loadPrepareCallback callback,
    void *context)
{
    _loadPrepareCallback = callback;
    _loadPrepareContext = context;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::setTargetHardwareId(
    std::string &targetHardwareId)
{
    this->targetHardwareId = targetHardwareId;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::setTargetHardwarePosition(
    std::string &targetHardwarePosition)
{
    this->targetHardwarePosition = targetHardwarePosition;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::setTargetHardwareIp(
    std::string &targetHardwareIp)
{
    this->targetHardwareIp = targetHardwareIp;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::setLoadList(
    std::vector<AuthenticationLoad> loadList)
{
    if (loadList.size() == 0)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }
    //We'll allow only one certificate per authentication
    if (loadList.size() > 1)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }
    this->loadList.clear();
    this->loadList = loadList;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::setTftpTargetHardwareServerPort(
    uint16_t port)
{
    tftpTargetHardwareServerPort = port;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::setTftpDataLoaderServerPort(
    uint16_t port)
{
    tftpDataLoaderServerPort = port;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::abort(
    uint16_t abortSource)
{
    this->abortSource = abortSource;
    toggleAbortSend = true;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::initTFTP()
{
    tftpClient = std::unique_ptr<TFTPClient>(new TFTPClient());
    if (tftpClient == nullptr)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }
    tftpServer = std::unique_ptr<TFTPServer>(new TFTPServer());
    if (tftpServer == nullptr)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    TftpClientOperationResult resultTftpClientOperation;
    resultTftpClientOperation = tftpClient->setConnection(
        targetHardwareIp.c_str(), tftpTargetHardwareServerPort);
    if (resultTftpClientOperation != TftpClientOperationResult::TFTP_CLIENT_OK)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    TftpServerOperationResult resultTftpServerOperation;
    resultTftpServerOperation = tftpServer->setPort(
        tftpDataLoaderServerPort);
    if (resultTftpServerOperation != TftpServerOperationResult::TFTP_SERVER_OK)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    //    resultTftpServerOperation = tftpServer->setTimeout(
    //            DEFAULT_Authentication_TFTP_TIMEOUT);
    //    if (resultTftpServerOperation != TftpServerOperationResult::TFTP_SERVER_OK)
    //    {
    //        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    //    }

    resultTftpServerOperation = tftpServer->registerOpenFileCallback(
        AuthenticationDataLoader::targetHardwareOpenFileRequest, this);
    if (resultTftpServerOperation != TftpServerOperationResult::TFTP_SERVER_OK)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    resultTftpServerOperation = tftpServer->registerCloseFileCallback(
        AuthenticationDataLoader::targetHardwareCloseFileRequest, this);
    if (resultTftpServerOperation != TftpServerOperationResult::TFTP_SERVER_OK)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    resultTftpServerOperation = tftpServer->registerSectionStartedCallback(
        AuthenticationDataLoader::targetHardwareSectionStarted, this);
    if (resultTftpServerOperation != TftpServerOperationResult::TFTP_SERVER_OK)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    resultTftpServerOperation = tftpServer->registerSectionFinishedCallback(
        AuthenticationDataLoader::targetHardwareSectionFinished, this);
    if (resultTftpServerOperation != TftpServerOperationResult::TFTP_SERVER_OK)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::initAuthenticationFiles(
    LoadAuthenticationRequestFile &loadAuthenticationRequestFile)
{
    for (AuthenticationLoad load : loadList)
    {
        std::string headerName = std::get<LOAD_FILE_NAME_IDX>(load);
        std::string loadPartNumberName = std::get<LOAD_PART_NUMBER_IDX>(load);

        LoadAuthenticationRequestHeaderFile headerFile;
        headerFile.setHeaderFileName(headerName);
        headerFile.setLoadPartNumberName(loadPartNumberName);
        loadAuthenticationRequestFile.addHeaderFile(headerFile);
    }
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::authenticate()
{
    abortSource = AUTHENTICATION_ABORT_SOURCE_NONE;
    endAuthentication = false;
    authenticationInitializationAccepted = false;
    authenticationCompleted = false;

    if (targetHardwareId.empty() || targetHardwarePosition.empty() || targetHardwareIp.empty())
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    if (loadList.size() == 0)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    std::shared_ptr<std::vector<uint8_t>> fileBuffer = std::make_shared<
        std::vector<uint8_t>>();
    if (fileBuffer == nullptr)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    /***************************************************************************
                                     START TFTP
    ***************************************************************************/
    if (initTFTP() != AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }
    std::thread serverThread = std::thread([this]
                                           { tftpServer->startListening(); });

    /***************************************************************************
                                INITIALIZATION
    ***************************************************************************/

    std::string baseFileName = targetHardwareId + std::string("_") + targetHardwarePosition;

    /********************* [TH_Authenticationing_Initialization] *********************/
    std::string initializationFileName = baseFileName + INITIALIZATION_AUTHENTICATION_FILE_EXTENSION;

    fileBuffer->clear();
    fileBuffer->resize(MAX_CERTIFICATE_BUFFER_SIZE);
    unsigned char *initializationFileBuffer = fileBuffer->data();
    memset(initializationFileBuffer, 0, fileBuffer->size());
    FILE *fpInitializationFile = fmemopen(initializationFileBuffer,
                                          fileBuffer->size(), "w");
    if (fpInitializationFile == NULL)
    {
        endAuthentication = true;
        tftpServer->stopListening();
        serverThread.join();
        fileBuffer.reset();
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    TftpClientOperationResult resultTftpClientOperation;
    int numTries = 0;
    do
    {
        fseek(fpInitializationFile, 0, SEEK_SET);
        // TODO: Check for wait msg
        resultTftpClientOperation = tftpClient->fetchFile(
            initializationFileName.c_str(), fpInitializationFile);
        numTries++;
    } while ((resultTftpClientOperation != TftpClientOperationResult::TFTP_CLIENT_OK) && (numTries < MAX_DLP_TRIES));
    fclose(fpInitializationFile);

    if (resultTftpClientOperation != TftpClientOperationResult::TFTP_CLIENT_OK)
    {
        endAuthentication = true;
        tftpServer->stopListening();
        serverThread.join();
        fileBuffer.reset();
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    InitializationAuthenticationFile initializationFile(initializationFileName);
    initializationFile.deserialize(fileBuffer);

    uint16_t operationAcceptanceStatusCode;
    initializationFile.getOperationAcceptanceStatusCode(
        operationAcceptanceStatusCode);

    if (_authenticationInitializationResponseContext != nullptr)
    {
        std::string jsonResponse("");
        initializationFile.serializeJSON(jsonResponse);
        _authenticationInitializationResponseCallback(
            jsonResponse,
            _authenticationInitializationResponseContext);
    }

    if (operationAcceptanceStatusCode !=
        OPERATION_IS_ACCEPTED)
    {
        tftpServer->stopListening();
        serverThread.join();
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    std::thread clientProcessorThread = std::thread([this]
                                                    { this->clientProcessor(); });

    /*********** Wait for status file with operation accepted code ***********/

    {
        std::unique_lock<std::mutex> lock(endAuthenticationMutex);
        filesProcessedCV.wait(lock, [this]
                              { return authenticationInitializationAccepted || endAuthentication; });
    }

    if (endAuthentication)
    {
        tftpServer->stopListening();
        serverThread.join();
        clientProcessorThread.join();
        fileBuffer.reset();
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    /****************************** [Load_List] ******************************/
    std::string loadListFileName = baseFileName + LOAD_AUTHENTICATION_REQUEST_FILE_EXTENSION;

    LoadAuthenticationRequestFile loadAuthenticationRequestFile(loadListFileName);
    initAuthenticationFiles(loadAuthenticationRequestFile);

    fileBuffer->clear();
    fileBuffer->resize(0);
    loadAuthenticationRequestFile.serialize(fileBuffer);

    // unsigned char *loadListFileBuffer = fileBuffer->data();
    FILE *fpLoadListFile = fmemopen(fileBuffer->data(),
                                    fileBuffer->size(), "r");
    numTries = 0;
    do
    {
        fseek(fpLoadListFile, 0, SEEK_SET);
        // TODO: Check for wait msg
        resultTftpClientOperation = tftpClient->sendFile(
            loadListFileName.c_str(), fpLoadListFile);
        numTries++;
    } while ((resultTftpClientOperation != TftpClientOperationResult::TFTP_CLIENT_OK) && (numTries < MAX_DLP_TRIES));
    fclose(fpLoadListFile);

    if (resultTftpClientOperation != TftpClientOperationResult::TFTP_CLIENT_OK)
    {
        endAuthentication = true;
        clientProcessorCV.notify_one();
        tftpServer->stopListening();
        serverThread.join();
        clientProcessorThread.join();
        fileBuffer.reset();
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    /***************************************************************************
                                   WAITING AUTHENTICATION
    ***************************************************************************/
    {
        std::unique_lock<std::mutex> lock(endAuthenticationMutex);
        endAuthenticationCV.wait(lock, [this]
                                 { return endAuthentication; });
    }

    tftpServer->stopListening();
    serverThread.join();
    clientProcessorThread.join();
    fileBuffer.reset();

    return authenticationCompleted ? AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK
                                   : AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
}

TftpServerOperationResult AuthenticationDataLoader::targetHardwareSectionStarted(
    ITFTPSection *sectionHandler, void *context)
{
    printf("Target hardware section started\n");
    if (context != nullptr)
    {
        AuthenticationDataLoader *thiz =
            static_cast<AuthenticationDataLoader *>(context);
        TftpSectionId id;
        sectionHandler->getSectionId(&id);
        std::shared_ptr<TargetClient> targetClient = std::make_shared<TargetClient>(id);
        {
            std::lock_guard<std::mutex> lock(thiz->targetClientsMutex);
            thiz->targetClients[id] = targetClient;
        }
    }

    return TftpServerOperationResult::TFTP_SERVER_OK;
}

TftpServerOperationResult AuthenticationDataLoader::targetHardwareSectionFinished(
    ITFTPSection *sectionHandler, void *context)
{
    if (context != nullptr)
    {
        AuthenticationDataLoader *thiz =
            static_cast<AuthenticationDataLoader *>(context);
        TftpSectionId id;
        sectionHandler->getSectionId(&id);
        {
            std::lock_guard<std::mutex> lock(thiz->targetClientsMutex);
            thiz->targetClients[id]->setSectionFinished();
        }
        thiz->clientProcessorCV.notify_one();
    }
    return TftpServerOperationResult::TFTP_SERVER_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::abortTargetRequest(
    uint16_t abortSource, ITFTPSection *sectionHandler, char *filename,
    char *mode)
{
    AuthenticationOperationResult result = AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    
    if (abortSource != AUTHENTICATION_ABORT_SOURCE_NONE)
    {
        result = AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;

        std::string lusExtension =
            std::string(LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION);

        if (std::strcmp(mode, "w") == 0 &&
            std::strstr(filename, lusExtension.c_str()) != nullptr)
        {
            toggleAbortSend = !toggleAbortSend;
            if (toggleAbortSend)
            {
                std::stringstream errorMessageStream;
                errorMessageStream << AUTHENTICATION_ABORT_MSG_PREFIX;
                errorMessageStream << AUTHENTICATION_ERROR_MSG_DELIMITER;
                errorMessageStream << std::hex << abortSource;
                std::string errorMessage = errorMessageStream.str();
                sectionHandler->setErrorMessage(errorMessage);
            }
            else
            {
                //Accept file
                result = AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
            }
        }
    }

    return result;
}

TftpServerOperationResult AuthenticationDataLoader::targetHardwareOpenFileRequest(
    ITFTPSection *sectionHandler, FILE **fp, char *filename, char *mode,
    size_t *bufferSize, void *context)
{
    printf("Target hardware open file request\n");
    AuthenticationDataLoader *thiz;
    if (context != nullptr)
    {
        thiz = static_cast<AuthenticationDataLoader *>(context);

        if (thiz->abortTargetRequest(thiz->abortSource, sectionHandler,
                                     filename, mode) == AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK)
        {
            (*fp) = NULL;
            return TftpServerOperationResult::TFTP_SERVER_ERROR;
        }

        if (std::strcmp(mode, "r") == 0)
        {
            *fp = fopen(filename, mode);
            if (bufferSize != nullptr)
            {
                *bufferSize = 0;
            }
            if (*fp == NULL)
            {
                uint16_t waitTime = DEFAULT_WAIT_TIME;
                if (thiz->_certificateNotAvailableCallback != nullptr)
                {
                    std::string fileNameStr(filename);
                    thiz->_certificateNotAvailableCallback(fileNameStr,
                                                    &waitTime,
                                                    thiz->_fileNotAvailableContext);
                }

                std::stringstream errorMessageStream;
                errorMessageStream << AUTHENTICATION_WAIT_MSG_PREFIX;
                errorMessageStream << AUTHENTICATION_ERROR_MSG_DELIMITER;
                errorMessageStream << waitTime;
                std::string errorMessage = errorMessageStream.str();
                sectionHandler->setErrorMessage(errorMessage);

                return TftpServerOperationResult::TFTP_SERVER_ERROR;
            }
            else if (thiz->_loadPrepareCallback != nullptr)
            {
                // std::string baseFileName = std::string(filename);
                // baseFileName = baseFileName.substr(0, baseFileName.find_last_of("."));
                // baseFileName = baseFileName.substr(baseFileName.find_last_of("/") + 1);
                thiz->_loadPrepareCallback(filename, fp, bufferSize, thiz->_loadPrepareContext);
            }
        }
        else
        {
            TftpSectionId id;
            sectionHandler->getSectionId(&id);
            {
                std::lock_guard<std::mutex> lock(thiz->targetClientsMutex);
                if (thiz->targetClients[id]->getClientFileBufferReference(fp) ==
                    AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK)
                {
                    thiz->targetClients[id]->setFileName(std::string(filename));
                }
            }
        }

        return TftpServerOperationResult::TFTP_SERVER_OK;
    }
    else
    {
        (*fp) = NULL;
    }

    return TftpServerOperationResult::TFTP_SERVER_ERROR;
}

TftpServerOperationResult AuthenticationDataLoader::targetHardwareCloseFileRequest(
    ITFTPSection *sectionHandler, FILE *fp, void *context)
{
    if (fp != NULL)
    {
        fclose(fp);
    }
    return TftpServerOperationResult::TFTP_SERVER_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::clientProcessor()
{
    while (!endAuthentication)
    {
        /*********************** Wait for client event ***********************/
        {
            std::unique_lock<std::mutex> lock(clientProcessorMutex);

            // TODO: Make Exception Timer from LAS and WAIT message override this
            clientProcessorCV.wait_for(lock,
                                       std::chrono::seconds(
                                           DEFAULT_AUTHENTICATION_DLP_TIMEOUT));
        }

        /************************ Process client event ***********************/
        endAuthentication = (targetClients.size() == 0);
        {
            std::lock_guard<std::mutex> lock(targetClientsMutex);
            for (std::unordered_map<TftpSectionId, std::shared_ptr<TargetClient>>::iterator it = targetClients.begin();
                 (it != targetClients.end()) && (!endAuthentication);)
            {
                bool sectionFinished, hasDataToProcess;
                (*it).second->isSectionFinished(sectionFinished);
                (*it).second->hasDataToProcess(hasDataToProcess);
                if (sectionFinished)
                {
                    if (hasDataToProcess)
                    {
                        std::string fileName;
                        char *buffer;
                        (*it).second->getFileName(fileName);
                        (*it).second->getClientBufferReference(&buffer);
                        if (buffer != NULL)
                        {
                            processFile(fileName, buffer);
                        }
                    }
                    it = targetClients.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
        filesProcessedCV.notify_one();
    }

    this->targetClients.clear();
    endAuthenticationCV.notify_one();

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::processFile(
    std::string fileName, char *buffer)
{
    if (fileName.find(LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION) != std::string::npos)
    {
        return processLoadAuthenticationStatusFile(buffer);
    }
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
}

AuthenticationOperationResult AuthenticationDataLoader::processLoadAuthenticationStatusFile(
    char *buffer)
{
    std::shared_ptr<std::vector<uint8_t>> data =
        std::make_shared<std::vector<uint8_t>>(buffer,
                                               buffer + MAX_CERTIFICATE_BUFFER_SIZE);

    std::string baseFileName = targetHardwareId + std::string("_") + targetHardwarePosition;
    std::string statusFileName = baseFileName + std::string(LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION);
    LoadAuthenticationStatusFile loadAuthenticationStatusFile(statusFileName);
    loadAuthenticationStatusFile.deserialize(data);

    if (_authenticationInformationStatusCallback != nullptr)
    {
        std::string jsonResponse("");
        loadAuthenticationStatusFile.serializeJSON(jsonResponse);
        printf("\n\n REPORT STATUS \n\n");
        _authenticationInformationStatusCallback(
            jsonResponse,
            _authenticationInformationStatusContext);
    }

    uint16_t authenticationOperationStatusCode;
    loadAuthenticationStatusFile.getAuthenticationOperationStatusCode(authenticationOperationStatusCode);
    switch (authenticationOperationStatusCode)
    {
    case STATUS_AUTHENTICATION_ACCEPTED:
        authenticationInitializationAccepted = true;
        break;
    case STATUS_AUTHENTICATION_COMPLETED:
        authenticationCompleted = true;
        endAuthentication = true;
        endAuthenticationCV.notify_one();
        break;
    case STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE:
    case STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_DL_REQUEST:
    case STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_OP_REQUEST:
        endAuthentication = true;
        endAuthenticationCV.notify_one();
        break;
    default:
        break;
    }

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationDataLoader::TargetClient::TargetClient(SectionId clientId)
{
    this->clientId = clientId;
    clientFileBuffer = NULL;
    sectionFinished = false;
    fileName = "";
}

AuthenticationDataLoader::TargetClient::~TargetClient()
{
    if (clientFileBuffer != NULL)
    {
        free(clientFileBuffer);
        clientFileBuffer = NULL;
    }
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::getClientId(
    SectionId &clientId)
{
    clientId = this->clientId;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::getClientFileBufferReference(
    FILE **fp)
{
    if (clientFileBuffer == NULL)
    {
        clientFileBuffer = (char *)malloc(MAX_CERTIFICATE_BUFFER_SIZE);
    }

    *fp = fmemopen(clientFileBuffer, MAX_CERTIFICATE_BUFFER_SIZE, "w");
    if (*fp == NULL)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    this->fileName = fileName;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::getClientBufferReference(
    char **buffer)
{
    *buffer = clientFileBuffer;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::setFileName(
    std::string fileName)
{
    this->fileName = fileName;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::getFileName(
    std::string &fileName)
{
    fileName = this->fileName;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::setSectionFinished()
{
    this->sectionFinished = true;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::isSectionFinished(
    bool &sectionFinished)
{
    sectionFinished = this->sectionFinished;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationDataLoader::TargetClient::hasDataToProcess(
    bool &hasDataToProcess)
{
    hasDataToProcess = (clientFileBuffer != NULL);
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}