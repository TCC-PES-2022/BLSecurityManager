#include "BaseAuthenticationFile.h"
#include <cstring>

BaseAuthenticationFile::BaseAuthenticationFile(std::string fileName,
                                               std::string protocolVersion)
{
    this->fileName = fileName;
    fileLength = sizeof(fileLength) + PROTOCOL_VERSION_SIZE;
    std::memset(this->protocolVersion, 0, PROTOCOL_VERSION_SIZE);

    size_t protocolVersionSize = std::min(protocolVersion.size(), PROTOCOL_VERSION_SIZE);
    std::memcpy(this->protocolVersion, protocolVersion.c_str(), protocolVersionSize);
}

BaseAuthenticationFile::~BaseAuthenticationFile()
{
}

FileAuthenticationOperationResult BaseAuthenticationFile::getProtocolVersion(std::string &protocolVersion)
{
    protocolVersion = std::string(2, '\0');
    protocolVersion[0] = this->protocolVersion[0];
    protocolVersion[1] = this->protocolVersion[1];
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult BaseAuthenticationFile::getFileLength(uint32_t &fileLength)
{
    fileLength = this->fileLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult BaseAuthenticationFile::getFileName(std::string &fileName)
{
    fileName = this->fileName;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

SerializableAuthenticationOperationResult BaseAuthenticationFile::serialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    data->push_back((fileLength >> 24) & 0xFF);
    data->push_back((fileLength >> 16) & 0xFF);
    data->push_back((fileLength >> 8) & 0xFF);
    data->push_back(fileLength & 0xFF);
    data->insert(data->end(), protocolVersion,
                 protocolVersion + PROTOCOL_VERSION_SIZE);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult BaseAuthenticationFile::deserialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    size_t offset = 0;
    if (data->size() < offset + sizeof(fileLength))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    fileLength = (data->at(offset) << 24) | (data->at(offset + 1) << 16) |
                 (data->at(offset + 2) << 8) | data->at(offset + 3);
    offset += sizeof(fileLength);

    if (data->size() < offset + PROTOCOL_VERSION_SIZE)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(protocolVersion, data->data() + offset, PROTOCOL_VERSION_SIZE);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult BaseAuthenticationFile::serializeJSON(std::string &data)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *fileNameJSON = cJSON_CreateString(fileName.c_str());
    if (fileNameJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "fileName", fileNameJSON);

    cJSON *fileLengthJSON = cJSON_CreateNumber(fileLength);
    if (fileLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "fileLength", fileLengthJSON);

    // Remember: protocolVersion is not null terminated
    std::string protocolVersionStr(3, '\0');
    protocolVersionStr[0] = protocolVersion[0];
    protocolVersionStr[1] = protocolVersion[1];
    cJSON *protocolVersionJSON = cJSON_CreateString(protocolVersionStr.c_str());
    if (protocolVersionJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "protocolVersion", protocolVersionJSON);

    char *serializedJSON = cJSON_PrintUnformatted(root);
    if (serializedJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    data = std::string(serializedJSON);
    free(serializedJSON);
    cJSON_Delete(root);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult BaseAuthenticationFile::deserializeJSON(std::string &data)
{
    cJSON *root = cJSON_Parse(data.c_str());
    if (root == NULL)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *fileNameJSON = cJSON_GetObjectItemCaseSensitive(root, "fileName");
    if (cJSON_IsString(fileNameJSON) && (fileNameJSON->valuestring != NULL))
    {
        fileName = std::string(fileNameJSON->valuestring);
    }
    else
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *fileLengthJSON = cJSON_GetObjectItemCaseSensitive(root, "fileLength");
    if (cJSON_IsNumber(fileLengthJSON))
    {
        fileLength = fileLengthJSON->valueint;
    }
    else
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *protocolVersionJSON = cJSON_GetObjectItemCaseSensitive(root, "protocolVersion");
    if (cJSON_IsString(protocolVersionJSON) && (protocolVersionJSON->valuestring != NULL))
    {
        std::memcpy(protocolVersion, protocolVersionJSON->valuestring, PROTOCOL_VERSION_SIZE);
    }
    else
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_Delete(root);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

FileAuthenticationOperationResult BaseAuthenticationFile::getFileSize(size_t &fileSize)
{
    fileSize = sizeof(fileLength) + PROTOCOL_VERSION_SIZE;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}
