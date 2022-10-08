#ifndef LOADAUTHENTICATIONSTATUSFILE_H
#define LOADAUTHENTICATIONSTATUSFILE_H

#include "BaseAuthenticationFile.h"
#include "LoadAuthenticationRequestFile.h"

#define MAX_AUTHENTICATION_STATUS_DESCRIPTION_SIZE static_cast<size_t>(255) // bytes
#define MAX_LOAD_STATUS_DESCRIPTION_SIZE static_cast<size_t>(255)           // bytes

#define MAX_HEADER_FILE_NAME_SIZE static_cast<size_t>(255)      // bytes
#define MAX_LOAD_PART_NUMBER_NAME_SIZE static_cast<size_t>(255) // bytes

/*
 * The Target accepts the operation (not yet started).
 */
#define STATUS_AUTHENTICATION_ACCEPTED static_cast<uint16_t>(0x0001)

/*
 * The operation is in progress.
 */
#define STATUS_AUTHENTICATION_IN_PROGRESS static_cast<uint16_t>(0x0002)

/*
 * The operation is completed without error.
 */
#define STATUS_AUTHENTICATION_COMPLETED static_cast<uint16_t>(0x0003)

/*
 * The operation is in progress, details provided in status description.
 */
#define STATUS_AUTHENTICATION_IN_PROGRESS_WITH_DESCRIPTION static_cast<uint16_t>(0x0004)

/*
 * The operation is aborted by the target hardware. Target hardware text is
 * required in the status description field to identify the reason for this
 * interruption.
 */
#define STATUS_AUTHENTICATION_ABORTED_BY_THE_TARGET_HARDWARE static_cast<uint16_t>(0x1003)

/*
 * The operation is aborted in the target hardware due to the receipt of an
 * abort error message sent by the data loader protocol.
 */
#define STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_DL_REQUEST static_cast<uint16_t>(0x1004)

/*
 * The operation is aborted in the target hardware due to the receipt of an
 * abort error message initiated by an operator action.
 */
#define STATUS_AUTHENTICATION_ABORTED_IN_THE_TARGET_OP_REQUEST static_cast<uint16_t>(0x1005)

/*
 * The load of this Header File has failed. Text is required in the "Status
 * Description" field to explain the failure.
 */
#define STATUS_AUTHENTICATION_HEAD_FILE_FAILED static_cast<uint16_t>(0x1007)

class LoadAuthenticationStatusHeaderFile : public ISerializable, public IFileAuthentication
{
public:
        LoadAuthenticationStatusHeaderFile();

        ~LoadAuthenticationStatusHeaderFile();

        /**
         * @brief Set Header File Name
         *
         * @param[in] headerFileName Header File Name.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setHeaderFileName(
            std::string headerFileName);

        /**
         * @brief Get Header File Name
         *
         * @param[out] headerFileName Header File Name.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getHeaderFileName(
            std::string &headerFileName);

        /**
         * @brief Get Header File Name Length
         *
         * @param[out] headerFileNameLength Header File Name Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getHeaderFileNameLength(
            uint8_t &headerFileNameLength);

        /**
         * @brief Set Load Part Number Name
         *
         * @param[in] loadPartNumber Part Number.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setLoadPartNumberName(std::string loadPartNumber);

        /**
         * @brief Get Load Part Number Name
         *
         * @param[out] loadPartNumber Part Number.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getLoadPartNumberName(std::string &loadPartNumber);

        /**
         * @brief Get Load Part Number Name Length
         *
         * @param[out] loadPartNumberLength Part Number Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getLoadPartNumberNameLength(
            uint8_t &loadPartNumberLength);

        /**
         * @brief Set Load Ratio
         *
         * @param[in] loadRatio Load Ratio.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setLoadRatio(uint32_t loadRatio);

        /**
         * @brief Get Load Ratio
         *
         * @param[out] loadRatio Load Ratio.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getLoadRatio(uint32_t &loadRatio);

        /**
         * @brief Set Load Status
         *
         * @param[in] loadStatus Load Status.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setLoadStatus(uint16_t loadStatus);

        /**
         * @brief Get Load Status
         *
         * @param[out] loadStatus Load Status.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getLoadStatus(uint16_t &loadStatus);

        /**
         * @brief Set Load Status Description
         *
         * @param[in] loadStatusDescription Load Status Description.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult
        setLoadStatusDescription(std::string loadStatusDescription);

        /**
         * @brief Get Load Status Description
         *
         * @param[out] loadStatusDescription Load Status Description.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult
        getLoadStatusDescription(std::string &loadStatusDescription);

        /**
         * @brief Get Load Status Description Length
         *
         * @param[out] loadStatusDescriptionLength Load Status Description Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult
        getLoadStatusDescriptionLength(uint8_t &loadStatusDescriptionLength);

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
        uint8_t headerFileNameLength;
        char headerFileName[MAX_HEADER_FILE_NAME_SIZE];
        uint8_t loadPartNumberNameLength;
        char loadPartNumberName[MAX_LOAD_PART_NUMBER_NAME_SIZE];
        uint32_t loadRatio; // This must be a 24-bit value
        uint16_t loadStatus;
        uint8_t loadStatusDescriptionLength;
        char loadStatusDescription[MAX_LOAD_STATUS_DESCRIPTION_SIZE];
};

class LoadAuthenticationStatusFile : public BaseAuthenticationFile
{
public:
        LoadAuthenticationStatusFile(std::string fileName = std::string(""),
                                     std::string protocolVersion =
                                         std::string(
                                             AUTHENTICATION_VERSION));

        virtual ~LoadAuthenticationStatusFile();

        /**
         * @brief Set Authentication Operation Status Code
         *
         * @param[in] authenticationOperationStatusCode Load Authentication Operation Status Code.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setAuthenticationOperationStatusCode(
            uint16_t authenticationOperationStatusCode);

        /**
         * @brief Get Authentication Operation Status Code
         *
         * @param[out] authenticationOperationStatusCode Load Authentication Operation Status Code.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getAuthenticationOperationStatusCode(
            uint16_t &authenticationOperationStatusCode);

        /**
         * @brief Set Authentication Status Description
         *
         * @param[in] authenticationStatusDescription Load Authentication Status Description.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setAuthenticationStatusDescription(
            std::string loadAuthenticationStatusDescription);

        /**
         * @brief Get Authentication Status Description
         *
         * @param[out] authenticationStatusDescription Load Authentication Status Description.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getAuthenticationStatusDescription(
            std::string &loadAuthenticationStatusDescription);

        /**
         * @brief Get Authentication Status Description Length
         *
         * @param[out] authenticationStatusDescriptionLength Load Authentication Status Description Length.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getAuthenticationStatusDescriptionLength(
            uint8_t &loadAuthenticationStatusDescriptionLength);

        /**
         * @brief Set Counter
         *
         * @param[in] counter Status counter
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setCounter(uint16_t counter);

        /**
         * @brief Get Counter
         *
         * @param[out] counter Status counter
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getCounter(uint16_t &counter);

        /**
         * @brief Set Exception Timer
         *
         * @param[in] exceptionTimer Exception Timer
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setExceptionTimer(uint16_t exceptionTimer);

        /**
         * @brief Get Exception Timer
         *
         * @param[out] exceptionTimer Exception Timer
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getExceptionTimer(uint16_t &exceptionTimer);

        /**
         * @brief Set Estimated Time
         *
         * @param[in] estimatedTime Estimated Time
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setEstimatedTime(uint16_t estimatedTime);

        /**
         * @brief Get Estimated Time
         *
         * @param[out] estimatedTime Estimated Time
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getEstimatedTime(uint16_t &estimatedTime);

        /**
         * @brief Set Load Ratio
         *
         * @param[in] loadListRatio Load List Ratio
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult setLoadListRatio(uint32_t loadListRatio);

        /**
         * @brief Get Load Ratio
         *
         * @param[out] loadListRatio Load List Ratio
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getLoadListRatio(uint32_t &loadListRatio);

        /**
         * @brief Add header file to the list.
         *
         * @param[in] headerFile Header file.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult addHeaderFile(
            LoadAuthenticationStatusHeaderFile &headerFile);

        /**
         * @brief Get all header files.
         *
         * @param[out] headerFiles List of header files.
         *
         * @return FILE_OPERATION_OK if success.
         * @return FILE_OPERATION_ERROR otherwise.
         */
        FileOperationResult getHeaderFiles(
            std::shared_ptr<std::vector<LoadAuthenticationStatusHeaderFile>> &headerFiles);

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
        uint16_t authenticationOperationStatusCode;
        uint8_t authenticationStatusDescriptionLength;
        char authenticationStatusDescription[MAX_AUTHENTICATION_STATUS_DESCRIPTION_SIZE];
        uint16_t counter;
        uint16_t exceptionTimer;
        uint16_t estimatedTime;
        uint32_t loadListRatio; // This must be a 24-bit value
        uint16_t numberOfHeaderFiles;
        std::shared_ptr<std::vector<LoadAuthenticationStatusHeaderFile>> headerFiles;
};

#endif // LOADAUTHENTICATIONSTATUSFILE_H
