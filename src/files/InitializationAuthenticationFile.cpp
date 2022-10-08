#include "InitializationAuthenticationFile.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

InitializationAuthenticationFile::InitializationAuthenticationFile(
    std::string fileName, std::string protocolVersion) : BaseAuthenticationFile(fileName, protocolVersion)
{
    operationAcceptanceStatusCode = 0;

    publicKeyLength = 0;
    std::memset(publicKey, 0, MAX_PUBLIC_KEY_SIZE);

    statusDescriptionLength = 0;
    std::memset(statusDescription, 0, MAX_STATUS_DESCRIPTION_SIZE);

    fileLength += sizeof(operationAcceptanceStatusCode) +
                  sizeof(publicKeyLength) +
                  sizeof(statusDescriptionLength);
}

InitializationAuthenticationFile::~InitializationAuthenticationFile()
{
}

FileOperationResult InitializationAuthenticationFile::setOperationAcceptanceStatusCode(
    uint16_t operationAcceptanceStatusCode)
{
    this->operationAcceptanceStatusCode = operationAcceptanceStatusCode;
    return FileOperationResult::FILE_OPERATION_OK;
}

FileOperationResult InitializationAuthenticationFile::getOperationAcceptanceStatusCode(
    uint16_t &operationAcceptanceStatusCode)
{
    operationAcceptanceStatusCode = this->operationAcceptanceStatusCode;
    return FileOperationResult::FILE_OPERATION_OK;
}

FileOperationResult InitializationAuthenticationFile::getPublicKeyLength(
    uint16_t &publicKeyLength)
{
    publicKeyLength = this->publicKeyLength;
    return FileOperationResult::FILE_OPERATION_OK;
}

FileOperationResult InitializationAuthenticationFile::setPublicKey(
    std::vector<uint8_t> &publicKey)
{
    if (publicKey.size() > MAX_PUBLIC_KEY_SIZE)
    {
        return FileOperationResult::FILE_OPERATION_ERROR;
    }

    fileLength -= publicKeyLength;
    publicKeyLength = publicKey.size();
    std::memcpy(this->publicKey, publicKey.data(), publicKeyLength);
    fileLength += publicKeyLength;
    return FileOperationResult::FILE_OPERATION_OK;
}

FileOperationResult InitializationAuthenticationFile::getPublicKey(
    std::vector<uint8_t> &publicKey)
{
    publicKey = std::vector<uint8_t>(this->publicKey, this->publicKey + publicKeyLength);
    return FileOperationResult::FILE_OPERATION_OK;
}

FileOperationResult InitializationAuthenticationFile::getStatusDescriptionLength(
    uint8_t &statusDescriptionLength)
{
    statusDescriptionLength = this->statusDescriptionLength;
    return FileOperationResult::FILE_OPERATION_OK;
}

FileOperationResult InitializationAuthenticationFile::setStatusDescription(
    std::string statusDescription)
{
    fileLength -= statusDescriptionLength;
    statusDescriptionLength = std::min(statusDescription.length() + 1,
                                       MAX_STATUS_DESCRIPTION_SIZE);
    std::memcpy(this->statusDescription, statusDescription.c_str(),
                statusDescriptionLength);
    if (statusDescriptionLength == MAX_STATUS_DESCRIPTION_SIZE)
    {
        // If the string is too long, we need to add a null terminator to the end
        this->statusDescription[statusDescriptionLength - 1] = '\0';
    }
    fileLength += statusDescriptionLength;
    return FileOperationResult::FILE_OPERATION_OK;
}

FileOperationResult InitializationAuthenticationFile::getStatusDescription(
    std::string &statusDescription)
{
    statusDescription = std::string(this->statusDescription);
    return FileOperationResult::FILE_OPERATION_OK;
}

SerializableOperationResult InitializationAuthenticationFile::serialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    SerializableOperationResult result = BaseAuthenticationFile::serialize(data);
    if (result != SerializableOperationResult::SERIALIZABLE_OK)
    {
        return result;
    }

    data->push_back((operationAcceptanceStatusCode >> 8) & 0xFF);
    data->push_back(operationAcceptanceStatusCode & 0xFF);
    data->push_back((publicKeyLength >> 8) & 0xFF);
    data->push_back(publicKeyLength & 0xFF);
    data->insert(data->end(), publicKey, publicKey + publicKeyLength);
    data->push_back(statusDescriptionLength);
    data->insert(data->end(), statusDescription,
                 statusDescription + statusDescriptionLength);

    return SerializableOperationResult::SERIALIZABLE_OK;
}

SerializableOperationResult InitializationAuthenticationFile::deserialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    SerializableOperationResult result = BaseAuthenticationFile::deserialize(data);
    if (result != SerializableOperationResult::SERIALIZABLE_OK)
    {
        return result;
    }

    size_t parentSize = 0;
    BaseAuthenticationFile::getFileSize(parentSize);
    size_t offset = parentSize;

    if (data->size() < offset + sizeof(operationAcceptanceStatusCode))
    {
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    operationAcceptanceStatusCode = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(operationAcceptanceStatusCode);

    if (data->size() < offset + sizeof(publicKeyLength))
    {
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    publicKeyLength = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(publicKeyLength);

    if (data->size() < offset + publicKeyLength)
    {
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    std::memcpy(publicKey, data->data() + offset, publicKeyLength);
    offset += publicKeyLength;

    if (data->size() < offset + sizeof(statusDescriptionLength))
    {
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    statusDescriptionLength = data->at(offset);
    offset += sizeof(statusDescriptionLength);

    if (data->size() < offset + statusDescriptionLength)
    {
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    std::memcpy(statusDescription, data->data() + offset, statusDescriptionLength);

    return SerializableOperationResult::SERIALIZABLE_OK;
}

SerializableOperationResult InitializationAuthenticationFile::serializeJSON(
    std::string &data)
{
    SerializableOperationResult result = BaseAuthenticationFile::serializeJSON(data);
    if (result != SerializableOperationResult::SERIALIZABLE_OK)
    {
        return result;
    }

    cJSON *root = cJSON_Parse(data.c_str());
    if (root == nullptr)
    {
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }

    cJSON *operationAcceptanceStatusCodeJSON = cJSON_CreateNumber(
        operationAcceptanceStatusCode);
    if (operationAcceptanceStatusCodeJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    cJSON_AddItemToObject(root, "operationAcceptanceStatusCode",
                          operationAcceptanceStatusCodeJSON);

    cJSON *publicKeyLengthJSON = cJSON_CreateNumber(publicKeyLength);
    if (publicKeyLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    cJSON_AddItemToObject(root, "publicKeyLength", publicKeyLengthJSON);

    std::stringstream publicKeyStream;
    for (size_t i = 0; i < publicKeyLength; i++)
    {
        publicKeyStream << std::hex << std::setfill('0') << std::setw(2)
                        << (int)publicKey[i];
    }
    std::string publicKeyString = publicKeyStream.str();
    cJSON *publicKeyJSON = cJSON_CreateString(publicKeyString.c_str());
    if (publicKeyJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    cJSON_AddItemToObject(root, "publicKey", publicKeyJSON);

    cJSON *statusDescriptionLengthJSON = cJSON_CreateNumber(
        statusDescriptionLength);
    if (statusDescriptionLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    cJSON_AddItemToObject(root, "statusDescriptionLength",
                          statusDescriptionLengthJSON);

    cJSON *statusDescriptionJSON = cJSON_CreateString(statusDescription);
    if (statusDescriptionJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    cJSON_AddItemToObject(root, "statusDescription", statusDescriptionJSON);

    char *serializedJSON = cJSON_PrintUnformatted(root);
    if (serializedJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    data = std::string(serializedJSON);
    free(serializedJSON);
    cJSON_Delete(root);

    return SerializableOperationResult::SERIALIZABLE_OK;
}

SerializableOperationResult InitializationAuthenticationFile::deserializeJSON(
    std::string &data)
{
    SerializableOperationResult result = BaseAuthenticationFile::deserializeJSON(data);
    if (result != SerializableOperationResult::SERIALIZABLE_OK)
    {
        return result;
    }

    cJSON *root = cJSON_Parse(data.c_str());
    if (root == nullptr)
    {
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }

    cJSON *operationAcceptanceStatusCodeJSON = cJSON_GetObjectItem(root,
                                                                   "operationAcceptanceStatusCode");
    if (operationAcceptanceStatusCodeJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    operationAcceptanceStatusCode = operationAcceptanceStatusCodeJSON->valueint;

    cJSON *publicKeyLengthJSON = cJSON_GetObjectItem(root, "publicKeyLength");
    if (publicKeyLengthJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    publicKeyLength = publicKeyLengthJSON->valueint;

    cJSON *publicKeyJSON = cJSON_GetObjectItem(root, "publicKey");
    if (publicKeyJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    std::string publicKeyString = std::string(publicKeyJSON->valuestring);
    if (publicKeyString.length() != publicKeyLength * 2)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    for (size_t i = 0; i < publicKeyLength; i++)
    {
        std::string byteString = publicKeyString.substr(i * 2, 2);
        publicKey[i] = (uint8_t)std::stoi(byteString, nullptr, 16);
    }

    cJSON *statusDescriptionLengthJSON = cJSON_GetObjectItem(root,
                                                             "statusDescriptionLength");
    if (statusDescriptionLengthJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    statusDescriptionLength = statusDescriptionLengthJSON->valueint;

    cJSON *statusDescriptionJSON = cJSON_GetObjectItem(root,
                                                       "statusDescription");
    if (statusDescriptionJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableOperationResult::SERIALIZABLE_ERROR;
    }
    std::string statusDescription = statusDescriptionJSON->valuestring;
    std::memcpy(this->statusDescription, statusDescription.c_str(),
                statusDescriptionLength);
    cJSON_Delete(root);

    return SerializableOperationResult::SERIALIZABLE_OK;
}

FileOperationResult InitializationAuthenticationFile::getFileSize(size_t &fileSize)
{
    FileOperationResult result = BaseAuthenticationFile::getFileSize(fileSize);
    if (result != FileOperationResult::FILE_OPERATION_OK)
    {
        return result;
    }

    fileSize += sizeof(operationAcceptanceStatusCode);
    fileSize += sizeof(publicKeyLength);
    fileSize += publicKeyLength;
    fileSize += sizeof(statusDescriptionLength);
    fileSize += statusDescriptionLength;

    return FileOperationResult::FILE_OPERATION_OK;
}