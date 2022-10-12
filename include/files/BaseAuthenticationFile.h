#ifndef BASEAUTHENTICATIONFILE_H
#define BASEAUTHENTICATIONFILE_H

#include <string>
#include <memory>
#include <vector>

#include "ISerializableAuthentication.h"
#include "IFileAuthentication.h"
#include <cjson/cJSON.h>

#define PROTOCOL_VERSION_SIZE static_cast<size_t>(2) // bytes

class BaseAuthenticationFile : public ISerializableAuthentication, public IFileAuthentication
{
public:
        BaseAuthenticationFile(std::string fileName = std::string(""),
                               std::string protocolVersion =
                                   std::string(AUTHENTICATION_VERSION));
        virtual ~BaseAuthenticationFile();

        /**
         * @brief Get Protocol Version
         *
         * @param[out] protocolVersion Protocol Version.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getProtocolVersion(
            std::string &protocolVersion);

        /**
         * @brief Get File Length
         *
         * @param[out] fileLength File Length.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getFileLength(
            uint32_t &fileLength);

        /**
         * @brief Get File Name
         *
         * @param[out] fileName File Name.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        virtual FileAuthenticationOperationResult getFileName(
            std::string &fileName);

        FileAuthenticationOperationResult getFileSize(size_t &fileSize) override;

        SerializableAuthenticationOperationResult serialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableAuthenticationOperationResult deserialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableAuthenticationOperationResult serializeJSON(
            std::string &data) override;

        SerializableAuthenticationOperationResult deserializeJSON(
            std::string &data) override;

protected:
        uint32_t fileLength;
        char protocolVersion[PROTOCOL_VERSION_SIZE];

        std::string fileName;
};

#endif // BASEAUTHENTICATIONFILE_H
