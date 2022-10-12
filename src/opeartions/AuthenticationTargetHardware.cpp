#include <stdio.h>
#include <algorithm>

#include "AuthenticationTargetHardware.h"
#include "InitializationAuthenticationFile.h"

#define STATUS_AUTHENTICATION_PERIOD 1000 // ms

AuthenticationTargetHardware::AuthenticationTargetHardware(
    std::string dataLoaderIp, int dataLoaderPort)
{
    this->dataLoaderIp = dataLoaderIp;
    this->dataLoaderPort = dataLoaderPort;

    _checkCertificateCallback = nullptr;
    _checkCertificateContext = NULL;
    // _transmissionCheckCallback = nullptr;
    // _transmissionCheckContext = NULL;
    _generateCryptographicKeyCallback = nullptr;
    _generateCryptographicKeyContext = NULL;

    authenticationStatusDescription.clear();

    loadAuthenticationInitializationFileBuffer = std::make_shared<std::vector<uint8_t>>();
    loadAuthenticationRequestFileBuffer = std::make_shared<std::vector<uint8_t>>();
    statusHeaderFiles = std::make_shared<std::vector<LoadAuthenticationStatusHeaderFile>>();

    authenticationOperationStatusCode = STATUS_AUTHENTICATION_ACCEPTED;
    currentState = AuthenticationTargetHardwareState::CREATED;
    nextState = AuthenticationTargetHardwareState::CREATED;

    runMainThread = true;
    runStatusThread = false;
    runAuthenticationThread = false;
    _mainThread = new std::thread(&AuthenticationTargetHardware::mainThread, this);

    loadListRatio = 0;
    authenticationAborted = false;
}

AuthenticationTargetHardware::~AuthenticationTargetHardware()
{
    runMainThread = false;
    nextState = AuthenticationTargetHardwareState::FINISHED;
    if (_mainThread->joinable())
    {
        _mainThreadCV.notify_one();
        _mainThread->join();
        delete _mainThread;
    }

    statusHeaderFiles->clear();
    statusHeaderFiles.reset();

    loadAuthenticationInitializationFileBuffer.reset();
    loadAuthenticationInitializationFileBuffer = nullptr;

    loadAuthenticationRequestFileBuffer.reset();
    loadAuthenticationRequestFileBuffer = nullptr;
}

AuthenticationOperationResult AuthenticationTargetHardware::registerCheckCertificateCallback(
    checkCertificateCallback callback, void *context)
{
    _checkCertificateCallback = callback;
    _checkCertificateContext = context;

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::registerGenerateCryptographicKeyCallback(
    generateCryptographicKeyCallback callback,
    void *context)
{
    _generateCryptographicKeyCallback = callback;
    _generateCryptographicKeyContext = context;

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

// AuthenticationOperationResult AuthenticationTargetHardware::registerTransmissionCheckCallback(
//     transmissionCheckCallback callback, void *context)
// {
//     _transmissionCheckCallback = callback;
//     _transmissionCheckContext = context;
//     return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
// }

AuthenticationOperationResult AuthenticationTargetHardware::checkAuthenticationConditions()
{
    // TODO: Make this a callback.
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::loadAuthenticationInitialization(
    FILE **fp, size_t *bufferSize, std::string &fileName)
{
    if (currentState != AuthenticationTargetHardwareState::CREATED)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    baseFileName = fileName.substr(0, fileName.find_last_of('.'));
    baseFileName = baseFileName.substr(baseFileName.find_last_of("/") + 1);

    InitializationAuthenticationFile loadAuthenticationInitializationResponse(fileName);
    if (checkAuthenticationConditions() == AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK)
    {
        loadAuthenticationInitializationResponse.setOperationAcceptanceStatusCode(
            OPERATION_IS_ACCEPTED);

        std::vector<uint8_t> cryptographicKey;
        if (_generateCryptographicKeyCallback != nullptr)
        {
            _generateCryptographicKeyCallback(baseFileName, cryptographicKey,
                                              _generateCryptographicKeyContext);
        }
        loadAuthenticationInitializationResponse.setCryptographicKey(cryptographicKey);

        nextState = AuthenticationTargetHardwareState::ACCEPTED;
    }
    else
    {
        loadAuthenticationInitializationResponse.setOperationAcceptanceStatusCode(
            OPERATION_IS_DENIED);
        nextState = AuthenticationTargetHardwareState::DENIED;
    }

    loadAuthenticationInitializationFileBuffer->clear();
    loadAuthenticationInitializationFileBuffer->resize(0);
    loadAuthenticationInitializationResponse.serialize(loadAuthenticationInitializationFileBuffer);

    (*fp) = fmemopen(loadAuthenticationInitializationFileBuffer->data(),
                     loadAuthenticationInitializationFileBuffer->size(), "r");
    if ((*fp) == NULL)
    {
        (*bufferSize) = 0;
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }
    (*bufferSize) = loadAuthenticationInitializationFileBuffer->size();

    _mainThreadCV.notify_one();

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::loadAuthenticationRequest(
    FILE **fp, size_t *bufferSize, std::string &fileName)
{
    if (currentState != AuthenticationTargetHardwareState::ACCEPTED &&
        // In case the accepted status was not received yet.
        nextState != AuthenticationTargetHardwareState::ACCEPTED)
    {
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    loadAuthenticationInitializationFileBuffer->clear();
    loadAuthenticationInitializationFileBuffer->resize(MAX_CERTIFICATE_BUFFER_SIZE);

    (*fp) = fmemopen(loadAuthenticationInitializationFileBuffer->data(),
                     loadAuthenticationInitializationFileBuffer->size(), "w");
    if ((*fp) == NULL)
    {
        if (bufferSize != NULL)
        {
            (*bufferSize) = 0;
        }
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }
    if (bufferSize != NULL)
    {
        (*bufferSize) = loadAuthenticationInitializationFileBuffer->size();
    }

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

NotifierAuthenticationOperationResult AuthenticationTargetHardware::notify(
    NotifierAuthenticationEventType event)
{
    switch (event)
    {
    case NotifierAuthenticationEventType::NOTIFIER_AUTHENTICATION_EVENT_TFTP_SECTION_CLOSED:
    {

        if (currentState != AuthenticationTargetHardwareState::ACCEPTED &&
            // In case the accepted status was not received yet.
            nextState != AuthenticationTargetHardwareState::ACCEPTED)
        {
            return NotifierAuthenticationOperationResult::NOTIFIER_ERROR;
        }

        std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> headerFiles;
        headerFiles = std::make_shared<std::vector<LoadAuthenticationRequestHeaderFile>>();
        LoadAuthenticationRequestFile loadAuthenticationRequestFile;

        if (loadAuthenticationRequestFile.deserialize(loadAuthenticationInitializationFileBuffer) == SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
        {
            loadAuthenticationRequestFile.getHeaderFiles(headerFiles);

            for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator it =
                     headerFiles->begin();
                 it != headerFiles->end(); ++it)
            {
                LoadAuthenticationStatusHeaderFile statusHeaderFile;

                std::string headerFileName;
                (*it).getHeaderFileName(headerFileName);
                statusHeaderFile.setHeaderFileName(headerFileName);

                std::string loadPartNumberName;
                (*it).getLoadPartNumberName(loadPartNumberName);
                statusHeaderFile.setLoadPartNumberName(loadPartNumberName);

                statusHeaderFile.setLoadRatio(0);
                statusHeaderFile.setLoadStatus(STATUS_AUTHENTICATION_ACCEPTED);
                statusHeaderFiles->push_back(statusHeaderFile);
            }

            nextState = AuthenticationTargetHardwareState::IN_PROGRESS;
            _mainThreadCV.notify_one();
        }
        else
        {
            return NotifierAuthenticationOperationResult::NOTIFIER_ERROR;
        }
        break;
    }
    default:
        return NotifierAuthenticationOperationResult::NOTIFIER_ERROR;
        break;
    }
    return NotifierAuthenticationOperationResult::NOTIFIER_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::abort(uint16_t abortSource)
{
    {
        std::lock_guard<std::mutex> lock(abortedMutex);
        if (authenticationAborted == true)
        {
            return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
        }
        authenticationAborted = true;
    }

    switch (abortSource)
    {
    case AUTHENTICATION_ABORT_SOURCE_TARGETHARDWARE:
        authenticationStatusDescription = "Authentication aborted by the target hardware.";
        nextState = AuthenticationTargetHardwareState::ABORTED_BY_TARGET;
        break;
    case AUTHENTICATION_ABORT_SOURCE_DATALOADER:
        authenticationStatusDescription = "Authentication aborted by the data loader.";
        nextState = AuthenticationTargetHardwareState::ABORTED_BY_DATALOADER;
        break;
    case AUTHENTICATION_ABORT_SOURCE_OPERATOR:
        authenticationStatusDescription = "Authentication aborted by the operator.";
        nextState = AuthenticationTargetHardwareState::ABORTED_BY_OPERATOR;
        break;
    default:
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
        break;
    }

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::getState(
    AuthenticationTargetHardwareState &state)
{
    state = currentState;
    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::mainThread()
{
    bool statusThreadStarted = false;
    std::thread *_statusThread;

    bool authenticationThreadStarted = false;
    std::thread *_authenticationThread;

    runStatusThread = false;
    runAuthenticationThread = false;

    while (runMainThread)
    {
        {
            std::unique_lock<std::mutex> lock(_mainThreadMutex);
            _mainThreadCV.wait(lock, [this]
                               { return currentState != nextState; });
        }

        switch (nextState)
        {
        case AuthenticationTargetHardwareState::ACCEPTED:
            runStatusThread = true;
            if (!statusThreadStarted)
            {
                _statusThread = new std::thread(&AuthenticationTargetHardware::statusThread, this);
                statusThreadStarted = true;
            }
            break;
        case AuthenticationTargetHardwareState::IN_PROGRESS:
        case AuthenticationTargetHardwareState::IN_PROGRESS_WITH_DESCRIPTION:
            runAuthenticationThread = true;
            if (!authenticationThreadStarted)
            {
                _authenticationThread = new std::thread(&AuthenticationTargetHardware::authenticationThread, this);
                authenticationThreadStarted = true;
            }
            break;
        case AuthenticationTargetHardwareState::COMPLETED:
        case AuthenticationTargetHardwareState::ABORTED_BY_TARGET:
        case AuthenticationTargetHardwareState::ABORTED_BY_DATALOADER:
        case AuthenticationTargetHardwareState::ABORTED_BY_OPERATOR:
            runAuthenticationThread = false;
            break;
        default:
            runMainThread = false;
            break;
        }
    }

    runStatusThread = false;
    if (statusThreadStarted && _statusThread->joinable())
    {
        _statusThread->join();
        delete _statusThread;
    }

    runAuthenticationThread = false;
    if (authenticationThreadStarted && _authenticationThread->joinable())
    {
        _authenticationThread->join();
        delete _authenticationThread;
    }

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

TftpClientOperationResult AuthenticationTargetHardware::tftpAuthenticationErrorCbk(
    short error_code, std::string &error_message, void *context)
{
    if (context != NULL && error_code == 0)
    {
        AuthenticationTargetHardware *authenticationTargetHardwareAuthentication =
            (AuthenticationTargetHardware *)context;

        std::string abortPrefix = std::string(AUTHENTICATION_ABORT_MSG_PREFIX) +
                                  std::string(AUTHENTICATION_ERROR_MSG_DELIMITER);
        size_t pos = error_message.find(abortPrefix);
        if (pos != std::string::npos)
        {
            pos = error_message.find(AUTHENTICATION_ERROR_MSG_DELIMITER);
            std::string abortCode = error_message.substr(
                pos + 1, error_message.length());

            authenticationTargetHardwareAuthentication->abort(std::stoul(abortCode, nullptr, 16));
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

            authenticationTargetHardwareAuthentication->authenticationWaitTime = std::stoi(waitSeconds);

            return TftpClientOperationResult::TFTP_CLIENT_OK;
        }
    }
    return TftpClientOperationResult::TFTP_CLIENT_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::statusThread()
{
    TFTPClient authenticationClient;
    authenticationClient.setConnection(dataLoaderIp.c_str(), dataLoaderPort);
    authenticationClient.registerTftpErrorCallback(AuthenticationTargetHardware::tftpAuthenticationErrorCbk, this);

    std::string statusFileName = baseFileName + LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION;

    std::shared_ptr<std::vector<uint8_t>> loadAuthenticationStatusFileBuffer = std::make_shared<std::vector<uint8_t>>();

    uint8_t sendRetry = MAX_DLP_TRIES;

    bool sendOnce = false;

    while (runStatusThread && !sendOnce && sendRetry > 0)
    {
        switch (nextState)
        {
        case AuthenticationTargetHardwareState::ACCEPTED:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_ACCEPTED;
            break;
        case AuthenticationTargetHardwareState::IN_PROGRESS:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_IN_PROGRESS;
            break;
        case AuthenticationTargetHardwareState::IN_PROGRESS_WITH_DESCRIPTION:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_IN_PROGRESS_WITH_DESCRIPTION;
            break;
        case AuthenticationTargetHardwareState::COMPLETED:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_COMPLETED;
            sendOnce = true;
            break;
        case AuthenticationTargetHardwareState::ABORTED_BY_TARGET:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE;
            sendOnce = true;
            break;
        case AuthenticationTargetHardwareState::ABORTED_BY_DATALOADER:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_DL_REQUEST;
            sendOnce = true;
            break;
        case AuthenticationTargetHardwareState::ABORTED_BY_OPERATOR:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_OP_REQUEST;
            sendOnce = true;
            break;
        default:
            authenticationOperationStatusCode = STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE;
            break;
        }

        // Prepare the status file
        LoadAuthenticationStatusFile loadAuthenticationStatusFile(statusFileName);

        loadAuthenticationStatusFile.setAuthenticationOperationStatusCode(authenticationOperationStatusCode);
        if (authenticationOperationStatusCode == STATUS_AUTHENTICATION_IN_PROGRESS_WITH_DESCRIPTION ||
            authenticationOperationStatusCode == STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE)
        {
            loadAuthenticationStatusFile.setAuthenticationStatusDescription(authenticationStatusDescription);
        }

        uint16_t counter;
        loadAuthenticationStatusFile.getCounter(counter);
        loadAuthenticationStatusFile.setCounter(++counter);
        loadAuthenticationStatusFile.setExceptionTimer(0);

        if (authenticationOperationStatusCode == STATUS_AUTHENTICATION_IN_PROGRESS ||
            authenticationOperationStatusCode == STATUS_AUTHENTICATION_IN_PROGRESS_WITH_DESCRIPTION)
        {
            loadAuthenticationStatusFile.setEstimatedTime(0xFFFF);
        }
        else
        {
            loadAuthenticationStatusFile.setEstimatedTime(0);
        }

        loadAuthenticationStatusFile.setLoadListRatio(loadListRatio);
        for (std::vector<LoadAuthenticationStatusHeaderFile>::iterator it =
                 statusHeaderFiles->begin();
             it != statusHeaderFiles->end(); ++it)
        {
            loadAuthenticationStatusFile.addHeaderFile(*it);
        }

        loadAuthenticationStatusFileBuffer->clear();
        loadAuthenticationStatusFileBuffer->resize(0);
        loadAuthenticationStatusFile.serialize(loadAuthenticationStatusFileBuffer);
        FILE *fp = fmemopen(loadAuthenticationStatusFileBuffer->data(),
                            loadAuthenticationStatusFileBuffer->size(), "r");

        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_ERROR;
        if (fp != NULL)
        {
            result = authenticationClient.sendFile(statusFileName.c_str(), fp);
            fclose(fp);
        }

        if (result == TftpClientOperationResult::TFTP_CLIENT_OK)
        {
            sendRetry = MAX_DLP_TRIES;
            currentState = nextState;
        }
        else
        {
            sendRetry--;
            sendOnce = false; // Will try again if we have retries left.
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(
            std::max(authenticationWaitTime, static_cast<uint16_t>(STATUS_AUTHENTICATION_PERIOD))));
    }

    if (sendRetry == 0)
    {
        nextState = AuthenticationTargetHardwareState::ERROR;
    }
    else
    {
        nextState = AuthenticationTargetHardwareState::FINISHED;
    }
    _mainThreadCV.notify_one();

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}

AuthenticationOperationResult AuthenticationTargetHardware::authenticationThread()
{
    TFTPClient authenticationClient;
    authenticationClient.setConnection(dataLoaderIp.c_str(), dataLoaderPort);
    authenticationClient.registerTftpErrorCallback(AuthenticationTargetHardware::tftpAuthenticationErrorCbk, this);

    uint8_t fetchRetry = MAX_DLP_TRIES;

    bool receiveError = false;

    uint32_t numOfSuccessfullAuthentications = 0;
    uint32_t numOfFilesToAuthentication = statusHeaderFiles->size();
    loadListRatio = 0;
    std::vector<LoadAuthenticationStatusHeaderFile>::iterator it;

    unsigned char fileBuffer[MAX_CERTIFICATE_BUFFER_SIZE];

    for (it = statusHeaderFiles->begin();
         (it != statusHeaderFiles->end()) && runAuthenticationThread;
         it = (authenticationWaitTime > 0) ? it : it + 1)
    {
        std::string headerFileName;
        (*it).getHeaderFileName(headerFileName);

        if (authenticationWaitTime > 0)
        {
            (*it).setLoadStatus(STATUS_AUTHENTICATION_IN_PROGRESS_WITH_DESCRIPTION);
            (*it).setLoadRatio(0);
            (*it).setLoadStatusDescription("Waiting " + std::to_string(authenticationWaitTime) +
                                           " seconds before authentication...");

            nextState = AuthenticationTargetHardwareState::IN_PROGRESS_WITH_DESCRIPTION;
            authenticationStatusDescription = "Waiting file " + headerFileName + " to be available...";
            _mainThreadCV.notify_one();
        }

        std::this_thread::sleep_for(std::chrono::seconds(authenticationWaitTime));
        authenticationWaitTime = 0;

        (*it).setLoadStatus(STATUS_AUTHENTICATION_IN_PROGRESS);
        (*it).setLoadRatio(0);

        nextState = AuthenticationTargetHardwareState::IN_PROGRESS_WITH_DESCRIPTION;
        _mainThreadCV.notify_one();

        // Remove file path if any
        // std::string cleanHeaderFileName = headerFileName;
        // size_t fileNamePosition = headerFileName.find_last_of("/\\");
        // if (fileNamePosition != std::string::npos)
        // {
        //     cleanHeaderFileName = headerFileName.substr(fileNamePosition + 1);
        // }

        FILE *fp = fmemopen(fileBuffer, MAX_CERTIFICATE_BUFFER_SIZE, "w");
        TftpClientOperationResult result = TftpClientOperationResult::TFTP_CLIENT_ERROR;
        if (fp != NULL)
        {
            do
            {
                result = authenticationClient.fetchFile(headerFileName.c_str(), fp);
            } while (result == TftpClientOperationResult::TFTP_CLIENT_ERROR &&
                     runAuthenticationThread && fetchRetry-- > 0 && authenticationWaitTime == 0);
            fclose(fp);
        }
        if (authenticationWaitTime > 0)
        {
            fetchRetry = MAX_DLP_TRIES;
            continue;
        }
        if (result != TftpClientOperationResult::TFTP_CLIENT_OK)
        {
            (*it).setLoadStatus(STATUS_AUTHENTICATION_HEAD_FILE_FAILED);
            (*it).setLoadStatusDescription("Failed to fetch header file");
            receiveError = true;
            break;
        }
        else
        {
            (*it).setLoadStatus(STATUS_AUTHENTICATION_IN_PROGRESS_WITH_DESCRIPTION);
            (*it).setLoadRatio(50);
            (*it).setLoadStatusDescription("Checking received file...");

            if (_checkCertificateCallback != nullptr)
            {
                std::string checkCertificateReport;
                if (_checkCertificateCallback(fileBuffer,
                                        MAX_CERTIFICATE_BUFFER_SIZE, checkCertificateReport,
                                        _checkCertificateContext) ==
                    AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR)
                {
                    (*it).setLoadStatus(STATUS_AUTHENTICATION_HEAD_FILE_FAILED);
                    (*it).setLoadStatusDescription(checkCertificateReport);
                    receiveError = true;
                    break;
                }
            }
            (*it).setLoadStatus(STATUS_AUTHENTICATION_COMPLETED);
            (*it).setLoadRatio(100);
            numOfSuccessfullAuthentications++;
            loadListRatio = (numOfSuccessfullAuthentications * 100) / numOfFilesToAuthentication;
        }
    }

    // In case of abort, define status of remaining files.
    while (it != statusHeaderFiles->end())
    {
        (*it).setLoadStatus(authenticationOperationStatusCode);
        (*it).setLoadStatusDescription(authenticationStatusDescription);
        it++;
    }

    if (receiveError)
    {
        abort(AUTHENTICATION_ABORT_SOURCE_TARGETHARDWARE);
        return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    }

    // if (_transmissionCheckCallback != nullptr)
    // {
    //     std::string checkCertificateReport;
    //     if (_transmissionCheckCallback(checkCertificateReport, _checkCertificateContext) ==
    //         AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR)
    //     {
    //         authenticationStatusDescription = checkCertificateReport;
    //         abort(AUTHENTICATION_ABORT_SOURCE_TARGETHARDWARE);
    //         return AuthenticationOperationResult::AUTHENTICATION_OPERATION_ERROR;
    //     }
    // }

    nextState = AuthenticationTargetHardwareState::COMPLETED;
    _mainThreadCV.notify_one();

    return AuthenticationOperationResult::AUTHENTICATION_OPERATION_OK;
}