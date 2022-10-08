#ifndef BASEAUTHENTICATIONFILE_H
#define BASEAUTHENTICATIONFILE_H

#include <string>
#include <memory>
#include <vector>

#include "ISerializable.h"
#include "IFileAuthentication.h"
#include <cjson/cJSON.h>

#define PROTOCOL_VERSION_SIZE static_cast<size_t>(2) // bytes

class BaseAuthenticationFile : public ISerializable, public IFileAuthentication
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
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getProtocolVersion(
            std::string &protocolVersion);

        /**
         * @brief Get File Length
         *
         * @param[out] fileLength File Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getFileLength(
            uint32_t &fileLength);

        /**
         * @brief Get File Name
         *
         * @param[out] fileName File Name.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        virtual FileOperationResult getFileName(
            std::string &fileName);

        FileOperationResult getFileSize(size_t &fileSize) override;

        SerializableOperationResult serialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableOperationResult deserialize(
            std::shared_ptr<std::vector<uint8_t>> &data) override;

        SerializableOperationResult serializeJSON(
            std::string &data) override;

        SerializableOperationResult deserializeJSON(
            std::string &data) override;

protected:
        uint32_t fileLength;
        char protocolVersion[PROTOCOL_VERSION_SIZE];

        std::string fileName;
};

#endif // BASEAUTHENTICATIONFILE_H
