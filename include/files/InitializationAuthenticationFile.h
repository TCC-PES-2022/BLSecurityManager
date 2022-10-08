#ifndef INITIALIZATIONAUTHENTICATIONFILE_H
#define INITIALIZATIONAUTHENTICATIONFILE_H

#include "BaseAuthenticationFile.h"

#define MAX_PUBLIC_KEY_SIZE static_cast<size_t>(512)         // bytes
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
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setOperationAcceptanceStatusCode(
            uint16_t operationAcceptanceStatusCode);

        /**
         * @brief Get Operation Operation Acceptance Status Code
         *
         * @param[out] operationAcceptanceStatusCode Operation Acceptance Status Code.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getOperationAcceptanceStatusCode(
            uint16_t &operationAcceptanceStatusCode);

        /**
         * @brief Get Public Key Length.
         *
         * @param[out] publicKeyLength Public Key Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getPublicKeyLength(
            uint16_t &publicKeyLength);

        /**
         * @brief Set Public Key.
         *
         * @param[in] publicKey Public Key.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setPublicKey(
            std::vector<uint8_t> &publicKey);

        /**
         * @brief Get Public Key.
         *
         * @param[out] publicKey Public Key.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getPublicKey(
            std::vector<uint8_t> &publicKey);

        /**
         * @brief Get Status Description Length
         *
         * @param[out] setStatusDescriptionLength Status Description Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getStatusDescriptionLength(
            uint8_t &statusDescriptionLength);

        /**
         * @brief Set Status Description
         *
         * @param[in] statusDescription Status Description.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setStatusDescription(
            std::string statusDescription);

        /**
         * @brief Get Status Description
         *
         * @param[out] statusDescription Status Description Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getStatusDescription(
            std::string &statusDescription);

        FileOperationResult getFileSize(size_t &fileSize) override;

        SerializableOperationResult serialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableOperationResult deserialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableOperationResult serializeJSON(
            std::string &data) override;

        SerializableOperationResult deserializeJSON(
            std::string &data) override;

private:
        uint16_t operationAcceptanceStatusCode;
        uint16_t publicKeyLength;
        uint8_t publicKey[MAX_PUBLIC_KEY_SIZE];
        uint8_t statusDescriptionLength;
        char statusDescription[MAX_STATUS_DESCRIPTION_SIZE];
};

#endif // INITIALIZATIONAUTHENTICATIONFILE_H
