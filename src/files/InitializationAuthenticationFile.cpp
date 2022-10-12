#include "InitializationAuthenticationFile.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

InitializationAuthenticationFile::InitializationAuthenticationFile(
    std::string fileName, std::string protocolVersion) : BaseAuthenticationFile(fileName, protocolVersion)
{
    operationAcceptanceStatusCode = 0;

    cryptographicKeyLength = 0;
    std::memset(cryptographicKey, 0, MAX_CRYPTOGRAPHIC_KEY_SIZE);

    statusDescriptionLength = 0;
    std::memset(statusDescription, 0, MAX_STATUS_DESCRIPTION_SIZE);

    fileLength += sizeof(operationAcceptanceStatusCode) +
                  sizeof(cryptographicKeyLength) +
                  sizeof(statusDescriptionLength);
}

InitializationAuthenticationFile::~InitializationAuthenticationFile()
{
}

FileAuthenticationOperationResult InitializationAuthenticationFile::setOperationAcceptanceStatusCode(
    uint16_t operationAcceptanceStatusCode)
{
    this->operationAcceptanceStatusCode = operationAcceptanceStatusCode;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::getOperationAcceptanceStatusCode(
    uint16_t &operationAcceptanceStatusCode)
{
    operationAcceptanceStatusCode = this->operationAcceptanceStatusCode;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::getCryptographicKeyLength(
    uint16_t &cryptographicKeyLength)
{
    cryptographicKeyLength = this->cryptographicKeyLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::setCryptographicKey(
    std::vector<uint8_t> &cryptographicKey)
{
    if (cryptographicKey.size() > MAX_CRYPTOGRAPHIC_KEY_SIZE)
    {
        return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_ERROR;
    }

    fileLength -= cryptographicKeyLength;
    cryptographicKeyLength = cryptographicKey.size();
    std::memcpy(this->cryptographicKey, cryptographicKey.data(), cryptographicKeyLength);
    fileLength += cryptographicKeyLength;
    printf("setCryptographicKey: %s\n", this->cryptographicKey);
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::getCryptographicKey(
    std::vector<uint8_t> &cryptographicKey)
{
    cryptographicKey = std::vector<uint8_t>(this->cryptographicKey, 
    this->cryptographicKey + cryptographicKeyLength);
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::getStatusDescriptionLength(
    uint8_t &statusDescriptionLength)
{
    statusDescriptionLength = this->statusDescriptionLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::setStatusDescription(
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
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::getStatusDescription(
    std::string &statusDescription)
{
    statusDescription = std::string(this->statusDescription);
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

SerializableAuthenticationOperationResult InitializationAuthenticationFile::serialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    SerializableAuthenticationOperationResult result = BaseAuthenticationFile::serialize(data);
    if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
    {
        return result;
    }

    data->push_back((operationAcceptanceStatusCode >> 8) & 0xFF);
    data->push_back(operationAcceptanceStatusCode & 0xFF);
    data->push_back((cryptographicKeyLength >> 8) & 0xFF);
    data->push_back(cryptographicKeyLength & 0xFF);
    data->insert(data->end(), cryptographicKey, cryptographicKey + cryptographicKeyLength);
    data->push_back(statusDescriptionLength);
    data->insert(data->end(), statusDescription,
                 statusDescription + statusDescriptionLength);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult InitializationAuthenticationFile::deserialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    SerializableAuthenticationOperationResult result = BaseAuthenticationFile::deserialize(data);
    if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
    {
        return result;
    }

    size_t parentSize = 0;
    BaseAuthenticationFile::getFileSize(parentSize);
    size_t offset = parentSize;

    if (data->size() < offset + sizeof(operationAcceptanceStatusCode))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    operationAcceptanceStatusCode = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(operationAcceptanceStatusCode);

    if (data->size() < offset + sizeof(cryptographicKeyLength))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cryptographicKeyLength = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(cryptographicKeyLength);

    if (data->size() < offset + cryptographicKeyLength)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(cryptographicKey, data->data() + offset, cryptographicKeyLength);
    offset += cryptographicKeyLength;

    if (data->size() < offset + sizeof(statusDescriptionLength))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    statusDescriptionLength = data->at(offset);
    offset += sizeof(statusDescriptionLength);

    if (data->size() < offset + statusDescriptionLength)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(statusDescription, data->data() + offset, statusDescriptionLength);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult InitializationAuthenticationFile::serializeJSON(
    std::string &data)
{
    SerializableAuthenticationOperationResult result = BaseAuthenticationFile::serializeJSON(data);
    if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
    {
        return result;
    }

    cJSON *root = cJSON_Parse(data.c_str());
    if (root == nullptr)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *operationAcceptanceStatusCodeJSON = cJSON_CreateNumber(
        operationAcceptanceStatusCode);
    if (operationAcceptanceStatusCodeJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "operationAcceptanceStatusCode",
                          operationAcceptanceStatusCodeJSON);

    cJSON *cryptographicKeyLengthJSON = cJSON_CreateNumber(cryptographicKeyLength);
    if (cryptographicKeyLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "cryptographicKeyLength", cryptographicKeyLengthJSON);

    std::stringstream cryptographicKeyStream;
    for (size_t i = 0; i < cryptographicKeyLength; i++)
    {
        cryptographicKeyStream << std::hex << std::setfill('0') << std::setw(2)
                        << (int)cryptographicKey[i];
    }
    std::string cryptographicKeyString = cryptographicKeyStream.str();
    cJSON *cryptographicKeyJSON = cJSON_CreateString(cryptographicKeyString.c_str());
    if (cryptographicKeyJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "cryptographicKey", cryptographicKeyJSON);

    cJSON *statusDescriptionLengthJSON = cJSON_CreateNumber(
        statusDescriptionLength);
    if (statusDescriptionLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "statusDescriptionLength",
                          statusDescriptionLengthJSON);

    cJSON *statusDescriptionJSON = cJSON_CreateString(statusDescription);
    if (statusDescriptionJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "statusDescription", statusDescriptionJSON);

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

SerializableAuthenticationOperationResult InitializationAuthenticationFile::deserializeJSON(
    std::string &data)
{
    SerializableAuthenticationOperationResult result = BaseAuthenticationFile::deserializeJSON(data);
    if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
    {
        return result;
    }

    cJSON *root = cJSON_Parse(data.c_str());
    if (root == nullptr)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *operationAcceptanceStatusCodeJSON = cJSON_GetObjectItem(root,
                                                                   "operationAcceptanceStatusCode");
    if (operationAcceptanceStatusCodeJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    operationAcceptanceStatusCode = operationAcceptanceStatusCodeJSON->valueint;

    cJSON *cryptographicKeyLengthJSON = cJSON_GetObjectItem(root, "cryptographicKeyLength");
    if (cryptographicKeyLengthJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cryptographicKeyLength = cryptographicKeyLengthJSON->valueint;

    cJSON *cryptographicKeyJSON = cJSON_GetObjectItem(root, "cryptographicKey");
    if (cryptographicKeyJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::string cryptographicKeyString = std::string(cryptographicKeyJSON->valuestring);
    if (cryptographicKeyString.length() != cryptographicKeyLength * 2)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    for (size_t i = 0; i < cryptographicKeyLength; i++)
    {
        std::string byteString = cryptographicKeyString.substr(i * 2, 2);
        cryptographicKey[i] = (uint8_t)std::stoi(byteString, nullptr, 16);
    }

    cJSON *statusDescriptionLengthJSON = cJSON_GetObjectItem(root,
                                                             "statusDescriptionLength");
    if (statusDescriptionLengthJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    statusDescriptionLength = statusDescriptionLengthJSON->valueint;

    cJSON *statusDescriptionJSON = cJSON_GetObjectItem(root,
                                                       "statusDescription");
    if (statusDescriptionJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::string statusDescription = statusDescriptionJSON->valuestring;
    std::memcpy(this->statusDescription, statusDescription.c_str(),
                statusDescriptionLength);
    cJSON_Delete(root);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

FileAuthenticationOperationResult InitializationAuthenticationFile::getFileSize(size_t &fileSize)
{
    FileAuthenticationOperationResult result = BaseAuthenticationFile::getFileSize(fileSize);
    if (result != FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK)
    {
        return result;
    }

    fileSize += sizeof(operationAcceptanceStatusCode);
    fileSize += sizeof(cryptographicKeyLength);
    fileSize += cryptographicKeyLength;
    fileSize += sizeof(statusDescriptionLength);
    fileSize += statusDescriptionLength;

    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}