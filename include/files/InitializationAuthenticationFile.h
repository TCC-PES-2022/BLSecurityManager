#ifndef INITIALIZATIONAUTHENTICATIONFILE_H
#define INITIALIZATIONAUTHENTICATIONFILE_H

#include "BaseAuthenticationFile.h"

//TODO: MAX_CRYPTOGRAPHIC_KEY_SIZE should be 512, but it's 65535 for now, as
//      we're sending the whole S-expression, not only the key.
#define MAX_CRYPTOGRAPHIC_KEY_SIZE static_cast<size_t>(65535)  // bytes
#define MAX_STATUS_DESCRIPTION_SIZE static_cast<size_t>(255) // bytes

/*
 * The operation is accepted.
 */
#define OPERATION_IS_ACCEPTED static_cast<uint16_t>(0x0001)

/*
 * The operation is denied. The reason is described in the status description
 * field.
 */
#define OPERATION_IS_DENIED static_cast<uint16_t>(0x1000)

/*
 * The operation is not supported by the Target
 */
#define OPERATION_IS_NOT_SUPPORTED static_cast<uint16_t>(0x1002)

class InitializationAuthenticationFile : public BaseAuthenticationFile
{
public:
        InitializationAuthenticationFile(std::string fileName = std::string(""),
                                         std::string protocolVersion =
                                             std::string(AUTHENTICATION_VERSION));
        virtual ~InitializationAuthenticationFile();

        /**
         * @brief Set Operation Operation Acceptance Status Code
         *
         * @param[in] operationAcceptanceStatusCode Operation Acceptance Status Code.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult setOperationAcceptanceStatusCode(
            uint16_t operationAcceptanceStatusCode);

        /**
         * @brief Get Operation Operation Acceptance Status Code
         *
         * @param[out] operationAcceptanceStatusCode Operation Acceptance Status Code.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getOperationAcceptanceStatusCode(
            uint16_t &operationAcceptanceStatusCode);

        /**
         * @brief Get Cryptographic Key length
         *
         * @param[out] cryptographicKeyLength Cryptographic Key Length.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getCryptographicKeyLength(
            uint16_t &cryptographicKeyLength);

        /**
         * @brief Set Cryptographic Key
         *
         * @param[in] cryptographicKey Cryptographic Key.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult setCryptographicKey(
            std::vector<uint8_t> &cryptographicKey);

        /**
         * @brief Get Cryptographic Key.
         *
         * @param[out] cryptographicKey Cryptographic Key.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getCryptographicKey(
            std::vector<uint8_t> &cryptographicKey);

        /**
         * @brief Get Status Description Length
         *
         * @param[out] setStatusDescriptionLength Status Description Length.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getStatusDescriptionLength(
            uint8_t &statusDescriptionLength);

        /**
         * @brief Set Status Description
         *
         * @param[in] statusDescription Status Description.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult setStatusDescription(
            std::string statusDescription);

        /**
         * @brief Get Status Description
         *
         * @param[out] statusDescription Status Description Length.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getStatusDescription(
            std::string &statusDescription);

        FileAuthenticationOperationResult getFileSize(size_t &fileSize) override;

        SerializableAuthenticationOperationResult serialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableAuthenticationOperationResult deserialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableAuthenticationOperationResult serializeJSON(
            std::string &data) override;

        SerializableAuthenticationOperationResult deserializeJSON(
            std::string &data) override;

private:
        uint16_t operationAcceptanceStatusCode;
        uint16_t cryptographicKeyLength;
        uint8_t cryptographicKey[MAX_CRYPTOGRAPHIC_KEY_SIZE];
        uint8_t statusDescriptionLength;
        char statusDescription[MAX_STATUS_DESCRIPTION_SIZE];
};

#endif // INITIALIZATIONAUTHENTICATIONFILE_H
