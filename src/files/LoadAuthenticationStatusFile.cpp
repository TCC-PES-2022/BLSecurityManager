#include "LoadAuthenticationStatusFile.h"
#include <cstring>

LoadAuthenticationStatusFile::LoadAuthenticationStatusFile(
    std::string fileName, std::string protocolVersion) : BaseAuthenticationFile(fileName, protocolVersion)
{
    std::memset(&authenticationStatusDescription, 0, MAX_AUTHENTICATION_STATUS_DESCRIPTION_SIZE);
    headerFiles = std::make_shared<std::vector<LoadAuthenticationStatusHeaderFile>>();
    headerFiles->clear();
    counter = 0;
    authenticationOperationStatusCode = 0;
    authenticationStatusDescriptionLength = 0;
    exceptionTimer = 0;
    estimatedTime = 0;
    loadListRatio = 0;
    numberOfHeaderFiles = 0;
    fileLength += sizeof(authenticationOperationStatusCode) +
                  sizeof(authenticationStatusDescriptionLength) +
                  sizeof(counter) +
                  sizeof(exceptionTimer) +
                  sizeof(estimatedTime) +
                  sizeof(loadListRatio) - sizeof(uint8_t) +
                  sizeof(numberOfHeaderFiles);
}

LoadAuthenticationStatusFile::~LoadAuthenticationStatusFile()
{
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::setAuthenticationOperationStatusCode(
    uint16_t authenticationOperationStatusCode)
{
    this->authenticationOperationStatusCode = authenticationOperationStatusCode;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::getAuthenticationOperationStatusCode(
    uint16_t &authenticationOperationStatusCode)
{
    authenticationOperationStatusCode = this->authenticationOperationStatusCode;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::setAuthenticationStatusDescription(
    std::string authenticationStatusDescription)
{
    fileLength -= authenticationStatusDescriptionLength;
    authenticationStatusDescriptionLength = std::min(authenticationStatusDescription.length() + 1,
                                                     MAX_AUTHENTICATION_STATUS_DESCRIPTION_SIZE);
    std::memcpy(this->authenticationStatusDescription, authenticationStatusDescription.c_str(),
                authenticationStatusDescriptionLength);
    if (authenticationStatusDescriptionLength == MAX_AUTHENTICATION_STATUS_DESCRIPTION_SIZE)
    {
        // If the string is too long, we need to add a null terminator to the end
        this->authenticationStatusDescription[authenticationStatusDescriptionLength - 1] = '\0';
    }
    fileLength += authenticationStatusDescriptionLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::getAuthenticationStatusDescription(
    std::string &authenticationStatusDescription)
{
    authenticationStatusDescription = std::string(this->authenticationStatusDescription);
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::getAuthenticationStatusDescriptionLength(
    uint8_t &authenticationStatusDescriptionLength)
{
    authenticationStatusDescriptionLength = this->authenticationStatusDescriptionLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::setCounter(uint16_t counter)
{
    this->counter = counter;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::getCounter(uint16_t &counter)
{
    counter = this->counter;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::setExceptionTimer(
    uint16_t exceptionTimer)
{
    this->exceptionTimer = exceptionTimer;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::getExceptionTimer(
    uint16_t &exceptionTimer)
{
    exceptionTimer = this->exceptionTimer;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::setEstimatedTime(
    uint16_t estimatedTime)
{
    this->estimatedTime = estimatedTime;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::getEstimatedTime(
    uint16_t &estimatedTime)
{
    estimatedTime = this->estimatedTime;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::setLoadListRatio(
    uint32_t loadListRatio)
{
    this->loadListRatio = loadListRatio;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusFile::getLoadListRatio(
    uint32_t &loadListRatio)
{
    loadListRatio = this->loadListRatio;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult
LoadAuthenticationStatusFile::addHeaderFile(
    LoadAuthenticationStatusHeaderFile &headerFile)
{
    std::string headerFileName;
    headerFile.getHeaderFileName(headerFileName);
    std::string loadPartNumberName;
    headerFile.getLoadPartNumberName(loadPartNumberName);

    if (headerFileName.empty() || loadPartNumberName.empty())
    {
        return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_ERROR;
    }

    headerFiles->push_back(headerFile);
    numberOfHeaderFiles++;

    size_t headerFileSize = 0;
    headerFile.getFileSize(headerFileSize);
    fileLength += headerFileSize;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult
LoadAuthenticationStatusFile::getHeaderFiles(
    std::shared_ptr<std::vector<LoadAuthenticationStatusHeaderFile>> &headerFiles)
{
    headerFiles = this->headerFiles;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

SerializableAuthenticationOperationResult LoadAuthenticationStatusFile::serialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    SerializableAuthenticationOperationResult result = BaseAuthenticationFile::serialize(data);
    if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
    {
        return result;
    }

    data->push_back((authenticationOperationStatusCode >> 8) & 0xFF);
    data->push_back(authenticationOperationStatusCode & 0xFF);

    data->push_back(authenticationStatusDescriptionLength);
    data->insert(data->end(), authenticationStatusDescription,
                 authenticationStatusDescription + authenticationStatusDescriptionLength);

    data->push_back((counter >> 8) & 0xFF);
    data->push_back(counter & 0xFF);

    data->push_back((exceptionTimer >> 8) & 0xFF);
    data->push_back(exceptionTimer & 0xFF);

    data->push_back((estimatedTime >> 8) & 0xFF);
    data->push_back(estimatedTime & 0xFF);

    data->push_back((loadListRatio >> 16) & 0xFF);
    data->push_back((loadListRatio >> 8) & 0xFF);
    data->push_back(loadListRatio & 0xFF);

    data->push_back((numberOfHeaderFiles >> 8) & 0xFF);
    data->push_back(numberOfHeaderFiles & 0xFF);

    for (std::vector<LoadAuthenticationStatusHeaderFile>::iterator it =
             headerFiles->begin();
         it != headerFiles->end(); ++it)
    {
        std::shared_ptr<std::vector<uint8_t>> headerFileData = std::make_shared<std::vector<uint8_t>>();
        result = it->serialize(headerFileData);
        if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
        {
            return result;
        }
        data->insert(data->end(), headerFileData->begin(), headerFileData->end());
    }

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult LoadAuthenticationStatusFile::deserialize(
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

    if (data->size() < offset + sizeof(authenticationOperationStatusCode))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    authenticationOperationStatusCode = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(authenticationOperationStatusCode);

    if (data->size() < offset + sizeof(authenticationStatusDescriptionLength))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    authenticationStatusDescriptionLength = data->at(offset);
    offset += sizeof(authenticationStatusDescriptionLength);

    if (data->size() < offset + authenticationStatusDescriptionLength)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(authenticationStatusDescription, data->data() + offset,
                authenticationStatusDescriptionLength);
    offset += authenticationStatusDescriptionLength;

    if (data->size() < offset + sizeof(counter))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    counter = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(counter);

    if (data->size() < offset + sizeof(exceptionTimer))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    exceptionTimer = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(exceptionTimer);

    if (data->size() < offset + sizeof(estimatedTime))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    estimatedTime = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(estimatedTime);

    if (data->size() < offset + sizeof(loadListRatio) - sizeof(uint8_t))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadListRatio = (data->at(offset) << 16) | (data->at(offset + 1) << 8) | data->at(offset + 2);
    offset += sizeof(loadListRatio) - sizeof(uint8_t);

    if (data->size() < offset + sizeof(numberOfHeaderFiles))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    numberOfHeaderFiles = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(numberOfHeaderFiles);

    if ((data->size() - offset) <= 0)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    for (int i = 0; i < numberOfHeaderFiles; i++)
    {
        std::vector<uint8_t> headerFileData(data->begin() + offset, data->end());
        std::shared_ptr<std::vector<uint8_t>> headerFileDataPtr =
            std::make_shared<std::vector<uint8_t>>(headerFileData);
        LoadAuthenticationStatusHeaderFile headerFile;
        result = headerFile.deserialize(headerFileDataPtr);
        if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
        {
            return result;
        }

        headerFiles->push_back(headerFile);

        size_t childSize = 0;
        headerFile.getFileSize(childSize);
        offset += childSize;
    }

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult LoadAuthenticationStatusFile::serializeJSON(
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

    cJSON *authenticationOperationStatusCodeJSON = cJSON_CreateNumber(authenticationOperationStatusCode);
    if (authenticationOperationStatusCodeJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "authenticationOperationStatusCode", authenticationOperationStatusCodeJSON);

    cJSON *authenticationStatusDescriptionLengthJSON = cJSON_CreateNumber(authenticationStatusDescriptionLength);
    if (authenticationStatusDescriptionLengthJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "authenticationStatusDescriptionLength", authenticationStatusDescriptionLengthJSON);

    cJSON *authenticationStatusDescriptionJSON = cJSON_CreateString(authenticationStatusDescription);
    if (authenticationStatusDescriptionJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "authenticationStatusDescription", authenticationStatusDescriptionJSON);

    cJSON *counterJSON = cJSON_CreateNumber(counter);
    if (counterJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "counter", counterJSON);

    cJSON *exceptionTimerJSON = cJSON_CreateNumber(exceptionTimer);
    if (exceptionTimerJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "exceptionTimer", exceptionTimerJSON);

    cJSON *estimatedTimeJSON = cJSON_CreateNumber(estimatedTime);
    if (estimatedTimeJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "estimatedTime", estimatedTimeJSON);

    cJSON *loadListRatioJSON = cJSON_CreateNumber(loadListRatio);
    if (loadListRatioJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "loadListRatio", loadListRatioJSON);

    cJSON *numberOfHeaderFilesJSON = cJSON_CreateNumber(numberOfHeaderFiles);
    if (numberOfHeaderFilesJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "numberOfHeaderFiles", numberOfHeaderFilesJSON);

    cJSON *headerFilesJSON = cJSON_CreateArray();
    if (headerFilesJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "headerFiles", headerFilesJSON);

    for (std::vector<LoadAuthenticationStatusHeaderFile>::iterator it =
             headerFiles->begin();
         it != headerFiles->end(); ++it)
    {
        std::string headerFileData;
        result = it->serializeJSON(headerFileData);
        if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
        {
            cJSON_Delete(root);
            return result;
        }
        cJSON *headerFileJSON = cJSON_Parse(headerFileData.c_str());
        if (headerFileJSON == nullptr)
        {
            cJSON_Delete(root);
            return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
        }
        cJSON_AddItemToArray(headerFilesJSON, headerFileJSON);
    }

    char *serializedData = cJSON_PrintUnformatted(root);
    if (serializedData == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    data = std::string(serializedData);
    free(serializedData);
    cJSON_Delete(root);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult LoadAuthenticationStatusFile::deserializeJSON(
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

    cJSON *authenticationOperationStatusCodeJSON = cJSON_GetObjectItem(root, "authenticationOperationStatusCode");
    if (authenticationOperationStatusCodeJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    authenticationOperationStatusCode = authenticationOperationStatusCodeJSON->valueint;

    cJSON *authenticationStatusDescriptionLengthJSON = cJSON_GetObjectItem(root, "authenticationStatusDescriptionLength");
    if (authenticationStatusDescriptionLengthJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    authenticationStatusDescriptionLength = authenticationStatusDescriptionLengthJSON->valueint;

    cJSON *authenticationStatusDescriptionJSON = cJSON_GetObjectItem(root, "authenticationStatusDescription");
    if (authenticationStatusDescriptionJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(authenticationStatusDescription, authenticationStatusDescriptionJSON->valuestring,
                authenticationStatusDescriptionLength);

    cJSON *counterJSON = cJSON_GetObjectItem(root, "counter");
    if (counterJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    counter = counterJSON->valueint;

    cJSON *exceptionTimerJSON = cJSON_GetObjectItem(root, "exceptionTimer");
    if (exceptionTimerJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    exceptionTimer = exceptionTimerJSON->valueint;

    cJSON *estimatedTimeJSON = cJSON_GetObjectItem(root, "estimatedTime");
    if (estimatedTimeJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    estimatedTime = estimatedTimeJSON->valueint;

    cJSON *loadListRatioJSON = cJSON_GetObjectItem(root, "loadListRatio");
    if (loadListRatioJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadListRatio = loadListRatioJSON->valueint;

    cJSON *numberOfHeaderFilesJSON = cJSON_GetObjectItem(root, "numberOfHeaderFiles");
    if (numberOfHeaderFilesJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    numberOfHeaderFiles = numberOfHeaderFilesJSON->valueint;

    cJSON *headerFilesJSON = cJSON_GetObjectItem(root, "headerFiles");
    if (headerFilesJSON == nullptr)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    int headerArraySize = cJSON_GetArraySize(headerFilesJSON);
    if (headerArraySize != numberOfHeaderFiles)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    for (int i = 0; i < numberOfHeaderFiles; i++)
    {
        cJSON *headerFileJSON = cJSON_GetArrayItem(headerFilesJSON, i);
        if (headerFileJSON == nullptr)
        {
            cJSON_Delete(root);
            return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
        }
        char *headerFileData = cJSON_PrintUnformatted(headerFileJSON);
        if (headerFileData == nullptr)
        {
            cJSON_Delete(root);
            return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
        }
        std::string data = std::string(headerFileData);
        LoadAuthenticationStatusHeaderFile headerFile;
        result = headerFile.deserializeJSON(data);
        free(headerFileData);
        if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
        {
            cJSON_Delete(root);
            return result;
        }
        std::string headerFileName;
        std::string loadPartNumberName;
        uint32_t loadRatio;
        uint16_t loadStatus;
        std::string loadStatusDescription;
        headerFile.getHeaderFileName(headerFileName);
        headerFile.getLoadPartNumberName(loadPartNumberName);
        headerFile.getLoadRatio(loadRatio);
        headerFile.getLoadStatus(loadStatus);
        headerFile.getLoadStatusDescription(loadStatusDescription);
        headerFiles->emplace_back();
        headerFiles->back().setHeaderFileName(headerFileName);
        headerFiles->back().setLoadPartNumberName(loadPartNumberName);
        headerFiles->back().setLoadRatio(loadRatio);
        headerFiles->back().setLoadStatus(loadStatus);
        headerFiles->back().setLoadStatusDescription(loadStatusDescription);
    }
    cJSON_Delete(root);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}
FileAuthenticationOperationResult LoadAuthenticationStatusFile::getFileSize(size_t &fileSize)
{
    FileAuthenticationOperationResult result = BaseAuthenticationFile::getFileSize(fileSize);
    if (result != FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK)
    {
        return result;
    }

    fileSize += sizeof(authenticationOperationStatusCode);
    fileSize += sizeof(authenticationStatusDescriptionLength);
    fileSize += authenticationStatusDescriptionLength;
    fileSize += sizeof(counter);
    fileSize += sizeof(exceptionTimer);
    fileSize += sizeof(estimatedTime);
    fileSize += sizeof(loadListRatio) - sizeof(uint8_t);
    fileSize += sizeof(numberOfHeaderFiles);

    for (std::vector<LoadAuthenticationStatusHeaderFile>::iterator it = headerFiles->begin();
         it != headerFiles->end(); it++)
    {
        size_t headerFileSize = 0;
        result = (*it).getFileSize(headerFileSize);
        if (result != FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK)
        {
            return result;
        }
        fileSize += headerFileSize;
    }

    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

LoadAuthenticationStatusHeaderFile::LoadAuthenticationStatusHeaderFile()
{
    headerFileNameLength = 0;
    std::memset(headerFileName, 0, sizeof(MAX_HEADER_FILE_NAME_SIZE));
    loadPartNumberNameLength = 0;
    std::memset(loadPartNumberName, 0, sizeof(MAX_LOAD_PART_NUMBER_NAME_SIZE));
    loadRatio = 0;
    loadStatus = 0;
    loadStatusDescriptionLength = 0;
    std::memset(loadStatusDescription, 0, sizeof(MAX_LOAD_STATUS_DESCRIPTION_SIZE));
}

LoadAuthenticationStatusHeaderFile::~LoadAuthenticationStatusHeaderFile()
{
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::setHeaderFileName(
    std::string headerFileName)
{
    if (headerFileName.empty())
    {
        return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_ERROR;
    }

    headerFileNameLength = std::min(headerFileName.length() + 1,
                                    MAX_HEADER_FILE_NAME_SIZE);
    std::memcpy(this->headerFileName, headerFileName.c_str(),
                headerFileNameLength);
    if (headerFileNameLength == MAX_HEADER_FILE_NAME_SIZE)
    {
        // If the string is too long, we need to add a null terminator to the end
        this->headerFileName[headerFileNameLength - 1] = '\0';
    }

    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::getHeaderFileName(
    std::string &headerFileName)
{
    headerFileName = std::string(this->headerFileName);
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::getHeaderFileNameLength(
    uint8_t &headerFileNameLength)
{
    headerFileNameLength = this->headerFileNameLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::setLoadPartNumberName(
    std::string loadPartNumberName)
{
    if (loadPartNumberName.empty())
    {
        return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_ERROR;
    }

    loadPartNumberNameLength = std::min(loadPartNumberName.length() + 1,
                                        MAX_LOAD_PART_NUMBER_NAME_SIZE);
    std::memcpy(this->loadPartNumberName, loadPartNumberName.c_str(),
                loadPartNumberNameLength);
    if (loadPartNumberNameLength == MAX_LOAD_PART_NUMBER_NAME_SIZE)
    {
        // If the string is too long, we need to add a null terminator to the end
        this->loadPartNumberName[loadPartNumberNameLength - 1] = '\0';
    }

    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult
LoadAuthenticationStatusHeaderFile::getLoadPartNumberName(
    std::string &loadPartNumberName)
{
    loadPartNumberName = std::string(this->loadPartNumberName);
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult
LoadAuthenticationStatusHeaderFile::getLoadPartNumberNameLength(
    uint8_t &loadPartNumberNameLength)
{
    loadPartNumberNameLength = this->loadPartNumberNameLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::setLoadRatio(
    uint32_t loadRatio)
{
    this->loadRatio = loadRatio;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::getLoadRatio(
    uint32_t &loadRatio)
{
    loadRatio = this->loadRatio;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::setLoadStatus(
    uint16_t loadStatus)
{
    this->loadStatus = loadStatus;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::getLoadStatus(
    uint16_t &loadStatus)
{
    loadStatus = this->loadStatus;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::setLoadStatusDescription(
    std::string loadStatusDescription)
{
    loadStatusDescriptionLength = std::min(loadStatusDescription.length() + 1,
                                           MAX_LOAD_STATUS_DESCRIPTION_SIZE);
    std::memcpy(this->loadStatusDescription, loadStatusDescription.c_str(),
                loadStatusDescriptionLength);
    if (loadStatusDescriptionLength == MAX_LOAD_STATUS_DESCRIPTION_SIZE)
    {
        // If the string is too long, we need to add a null terminator to the end
        this->loadStatusDescription[loadStatusDescriptionLength - 1] = '\0';
    }

    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::getLoadStatusDescription(
    std::string &loadStatusDescription)
{
    loadStatusDescription = std::string(this->loadStatusDescription);
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::getLoadStatusDescriptionLength(
    uint8_t &loadStatusDescriptionLength)
{
    loadStatusDescriptionLength = this->loadStatusDescriptionLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationStatusHeaderFile::serialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    data->push_back(headerFileNameLength);
    data->insert(data->end(), headerFileName,
                 headerFileName + headerFileNameLength);
    data->push_back(loadPartNumberNameLength);
    data->insert(data->end(), loadPartNumberName,
                 loadPartNumberName + loadPartNumberNameLength);
    data->push_back((loadRatio >> 16) & 0xFF);
    data->push_back((loadRatio >> 8) & 0xFF);
    data->push_back(loadRatio & 0xFF);
    data->push_back((loadStatus >> 8) & 0xFF);
    data->push_back(loadStatus & 0xFF);
    data->push_back(loadStatusDescriptionLength);
    data->insert(data->end(), loadStatusDescription,
                 loadStatusDescription + loadStatusDescriptionLength);
    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationStatusHeaderFile::deserialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    size_t offset = 0;

    if (data->size() < offset + sizeof(headerFileNameLength))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    headerFileNameLength = data->at(offset);
    offset += sizeof(headerFileNameLength);

    if (data->size() < offset + headerFileNameLength)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(headerFileName, data->data() + offset, headerFileNameLength);
    offset += headerFileNameLength;

    if (data->size() < offset + sizeof(loadPartNumberNameLength))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    loadPartNumberNameLength = data->at(offset);
    offset += sizeof(loadPartNumberNameLength);

    if (data->size() < offset + loadPartNumberNameLength)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(loadPartNumberName, data->data() + offset, loadPartNumberNameLength);
    offset += loadPartNumberNameLength;

    if (data->size() < offset + sizeof(loadRatio) - sizeof(uint8_t))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadRatio = (data->at(offset) << 16) | (data->at(offset + 1) << 8) | data->at(offset + 2);
    offset += sizeof(loadRatio) - sizeof(uint8_t);

    if (data->size() < offset + sizeof(loadStatus))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadStatus = (data->at(offset) << 8) | data->at(offset + 1);
    offset += sizeof(loadStatus);

    if (data->size() < offset + sizeof(loadStatusDescriptionLength))
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadStatusDescriptionLength = data->at(offset);
    offset += sizeof(loadStatusDescriptionLength);

    if (data->size() < offset + loadStatusDescriptionLength)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(loadStatusDescription, data->data() + offset, loadStatusDescriptionLength);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationStatusHeaderFile::serializeJSON(std::string &data)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *headerFileNameLengthJSON = cJSON_CreateNumber(headerFileNameLength);
    if (headerFileNameLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "headerFileNameLength", headerFileNameLengthJSON);

    cJSON *headerFileNameJSON = cJSON_CreateString(headerFileName);
    if (headerFileNameJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "headerFileName", headerFileNameJSON);

    cJSON *loadPartNumberNameLengthJSON = cJSON_CreateNumber(loadPartNumberNameLength);
    if (loadPartNumberNameLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "loadPartNumberNameLength", loadPartNumberNameLengthJSON);

    cJSON *loadPartNumberNameJSON = cJSON_CreateString(loadPartNumberName);
    if (loadPartNumberNameJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "loadPartNumberName", loadPartNumberNameJSON);

    cJSON *loadRatioJSON = cJSON_CreateNumber(loadRatio);
    if (loadRatioJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "loadRatio", loadRatioJSON);

    cJSON *loadStatusJSON = cJSON_CreateNumber(loadStatus);
    if (loadStatusJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "loadStatus", loadStatusJSON);

    cJSON *loadStatusDescriptionLengthJSON = cJSON_CreateNumber(loadStatusDescriptionLength);
    if (loadStatusDescriptionLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "loadStatusDescriptionLength", loadStatusDescriptionLengthJSON);

    cJSON *loadStatusDescriptionJSON = cJSON_CreateString(loadStatusDescription);
    if (loadStatusDescriptionJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    cJSON_AddItemToObject(root, "loadStatusDescription", loadStatusDescriptionJSON);

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

SerializableAuthenticationOperationResult
LoadAuthenticationStatusHeaderFile::deserializeJSON(std::string &data)
{
    cJSON *root = cJSON_Parse(data.c_str());
    if (root == NULL)
    {
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }

    cJSON *headerFileNameLengthJSON = cJSON_GetObjectItemCaseSensitive(root, "headerFileNameLength");
    if (headerFileNameLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    headerFileNameLength = headerFileNameLengthJSON->valueint;

    cJSON *headerFileNameJSON = cJSON_GetObjectItemCaseSensitive(root, "headerFileName");
    if (headerFileNameJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(headerFileName, headerFileNameJSON->valuestring, headerFileNameLength);

    cJSON *loadPartNumberNameLengthJSON = cJSON_GetObjectItemCaseSensitive(root, "loadPartNumberNameLength");
    if (loadPartNumberNameLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadPartNumberNameLength = loadPartNumberNameLengthJSON->valueint;

    cJSON *loadPartNumberNameJSON = cJSON_GetObjectItemCaseSensitive(root, "loadPartNumberName");
    if (loadPartNumberNameJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(loadPartNumberName, loadPartNumberNameJSON->valuestring, loadPartNumberNameLength);

    cJSON *loadRatioJSON = cJSON_GetObjectItemCaseSensitive(root, "loadRatio");
    if (loadRatioJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadRatio = loadRatioJSON->valueint;

    cJSON *loadStatusJSON = cJSON_GetObjectItemCaseSensitive(root, "loadStatus");
    if (loadStatusJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadStatus = loadStatusJSON->valueint;

    cJSON *loadStatusDescriptionLengthJSON = cJSON_GetObjectItemCaseSensitive(root, "loadStatusDescriptionLength");
    if (loadStatusDescriptionLengthJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    loadStatusDescriptionLength = loadStatusDescriptionLengthJSON->valueint;

    cJSON *loadStatusDescriptionJSON = cJSON_GetObjectItemCaseSensitive(root, "loadStatusDescription");
    if (loadStatusDescriptionJSON == NULL)
    {
        cJSON_Delete(root);
        return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_ERROR;
    }
    std::memcpy(loadStatusDescription, loadStatusDescriptionJSON->valuestring, loadStatusDescriptionLength);

    cJSON_Delete(root);
    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationStatusHeaderFile::getFileSize(
    size_t &fileSize)
{
    fileSize = sizeof(headerFileNameLength);
    fileSize += headerFileNameLength;
    fileSize += sizeof(loadPartNumberNameLength);
    fileSize += loadPartNumberNameLength;
    fileSize += sizeof(loadRatio) - sizeof(uint8_t);
    fileSize += sizeof(loadStatus);
    fileSize += sizeof(loadStatusDescriptionLength);
    fileSize += loadStatusDescriptionLength;

    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}
