#ifndef LOADAUTHENTICATIONREQUESTFILE_H
#define LOADAUTHENTICATIONREQUESTFILE_H

#include "BaseAuthenticationFile.h"

#define MAX_HEADER_FILE_NAME_SIZE static_cast<size_t>(255)      // bytes
#define MAX_LOAD_PART_NUMBER_NAME_SIZE static_cast<size_t>(255) // bytes

class LoadAuthenticationRequestHeaderFile : public ISerializableAuthentication, public IFileAuthentication
{
public:
        LoadAuthenticationRequestHeaderFile();
        ~LoadAuthenticationRequestHeaderFile();

        /**
         * @brief Set Header File Name
         *
         * @param[in] headerFileName Header File Name.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult setHeaderFileName(
            std::string headerFileName);

        /**
         * @brief Get Header File Name
         *
         * @param[out] headerFileName Header File Name.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getHeaderFileName(std::string &headerFileName);

        /**
         * @brief Set Load Part Number Name
         *
         * @param[in] loadPartNumber Part Number Name
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult setLoadPartNumberName(std::string loadPartNumber);

        /**
         * @brief Get Load Part Number Name
         *
         * @param[out] loadPartNumberName Load Part Number Name.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getLoadPartNumberName(std::string &loadPartNumberName);

        /**
         * @brief Get Header File Name Length
         *
         * @param[out] headerFileNameLength Header File Name Length.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getHeaderFileNameLength(uint8_t &headerFileNameLength);

        /**
         * @brief Get Load Part Number Name Length
         *
         * @param[out] loadPartNumberNameLength Load Part Number Name Length.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getLoadPartNumberNameLength(uint8_t &loadPartNumberNameLength);

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
        uint8_t headerFileNameLength;
        char headerFileName[MAX_HEADER_FILE_NAME_SIZE];
        uint8_t loadPartNumberNameLength;
        char loadPartNumberName[MAX_LOAD_PART_NUMBER_NAME_SIZE];
};

class LoadAuthenticationRequestFile : public BaseAuthenticationFile
{
public:
        LoadAuthenticationRequestFile(std::string fileName = std::string(""),
                                      std::string protocolVersion =
                                          std::string(AUTHENTICATION_VERSION));
        virtual ~LoadAuthenticationRequestFile();

        /**
         * @brief Add header file to the list.
         *
         * @param[in] headerFile Header file.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult addHeaderFile(
            LoadAuthenticationRequestHeaderFile &headerFile);
        /**
         * @brief Get all header files.
         *
         * @param[out] headerFiles List of header files.
         *
         * @return FILE_AUTHENTICATION_OPERATION_OK if success.
         * @return FILE_AUTHENTICATION_OPERATION_ERROR otherwise.
         */
        FileAuthenticationOperationResult getHeaderFiles(
            std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> &headerFiles);

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
        uint16_t numberOfHeaderFiles;
        std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> headerFiles;
};

#endif // LOADAUTHENTICATIONREQUESTFILE_H
