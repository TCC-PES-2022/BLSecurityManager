#ifndef AUTHENTICATIONBASE_H
#define AUTHENTICATIONBASE_H

#include <vector>
#include <memory>

#include "TFTPClient.h"

#define INITIALIZATION_AUTHENTICATION_FILE_EXTENSION std::string(".LAI")
#define LOAD_AUTHENTICATION_REQUEST_FILE_EXTENSION std::string(".LAR")
#define LOAD_AUTHENTICATION_STATUS_FILE_EXTENSION std::string(".LAS")

#define DEFAULT_AUTHENTICATION_TFTP_PORT 59
#define DEFAULT_AUTHENTICATION_TFTP_TIMEOUT 2 // seconds
#define DEFAULT_AUTHENTICATION_DLP_TIMEOUT 13 // seconds
#define DEFAULT_AUTHENTICATION_WAIT_TIME 1    // second
#define MAX_DLP_TRIES 2

// This size must be enough to store the certificate transmission.
// TODO: make it dynamic?
#define MAX_CERTIFICATE_BUFFER_SIZE (10 * 1024)

/**
 * @brief Enum with possible return from interface functions.
 * Possible return values are:
 * - AUTHENTICATION_OPERATION_OK:                    Operation was successful.
 * - AUTHENTICATION_OPERATION_ERROR:                 Generic error.
 */
enum class AuthenticationOperationResult
{
    AUTHENTICATION_OPERATION_OK = 0,
    AUTHENTICATION_OPERATION_ERROR
};

#define AUTHENTICATION_ABORT_SOURCE_NONE 0
#define AUTHENTICATION_ABORT_SOURCE_TARGETHARDWARE 0x1003
#define AUTHENTICATION_ABORT_SOURCE_DATALOADER 0x1004
#define AUTHENTICATION_ABORT_SOURCE_OPERATOR 0x1005

#define AUTHENTICATION_ABORT_MSG_PREFIX "ABORT"
#define AUTHENTICATION_WAIT_MSG_PREFIX "WAIT"
#define AUTHENTICATION_ERROR_MSG_DELIMITER ":"

/**
 * @brief Base class for Authentication operations.
 */
class AuthenticationBase
{
public:
    virtual ~AuthenticationBase() = default;

    /**
     * @brief Abort authentication operation.
     *
     * @param[in] abortSource the abort source.
     *
     * @return AUTHENTICATION_OPERATION_OK if success.
     * @return AUTHENTICATION_OPERATION_ERROR otherwise.
     */
    virtual AuthenticationOperationResult abort(uint16_t abortSource) = 0;

protected:
    std::unique_ptr<ITFTPClient> tftpClient;
};

#endif // AUTHENTICATIONBASE_H
