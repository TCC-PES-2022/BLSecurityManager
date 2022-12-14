#include "LoadAuthenticationRequestFile.h"
#include <cstring>

LoadAuthenticationRequestFile::LoadAuthenticationRequestFile(
    std::string fileName, std::string protocolVersion) : BaseAuthenticationFile(fileName, protocolVersion)
{
    headerFiles = std::make_shared<std::vector<LoadAuthenticationRequestHeaderFile>>();
    headerFiles->clear();
    numberOfHeaderFiles = 0;
    fileLength += sizeof(numberOfHeaderFiles);
}

LoadAuthenticationRequestFile::~LoadAuthenticationRequestFile()
{
    headerFiles->clear();
    headerFiles.reset();
    headerFiles = nullptr;
}

FileAuthenticationOperationResult
LoadAuthenticationRequestFile::addHeaderFile(
    LoadAuthenticationRequestHeaderFile &headerFile)
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
LoadAuthenticationRequestFile::getHeaderFiles(
    std::shared_ptr<std::vector<LoadAuthenticationRequestHeaderFile>> &headerFiles)
{
    headerFiles = this->headerFiles;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationRequestFile::serialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    SerializableAuthenticationOperationResult result = BaseAuthenticationFile::serialize(data);
    if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
    {
        return result;
    }

    uint16_t numberOfHeaderFiles = headerFiles->size();
    data->push_back((numberOfHeaderFiles >> 8) & 0xFF);
    data->push_back(numberOfHeaderFiles & 0xFF);

    for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator it =
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

SerializableAuthenticationOperationResult
LoadAuthenticationRequestFile::deserialize(
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

    for (uint16_t i = 0; i < numberOfHeaderFiles; i++)
    {
        std::vector<uint8_t> headerFileData(data->begin() + offset, data->end());
        std::shared_ptr<std::vector<uint8_t>> headerFileDataPtr =
            std::make_shared<std::vector<uint8_t>>(headerFileData);
        LoadAuthenticationRequestHeaderFile headerFile;
        result = headerFile.deserialize(headerFileDataPtr);
        if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
        {
            return result;
        }

        std::string headerFileName;
        std::string loadPartNumberName;
        headerFile.getHeaderFileName(headerFileName);
        headerFile.getLoadPartNumberName(loadPartNumberName);
        headerFiles->emplace_back();
        headerFiles->back().setHeaderFileName(headerFileName);
        headerFiles->back().setLoadPartNumberName(loadPartNumberName);

        uint8_t headerFileNameLength;
        uint8_t loadPartNumberNameLength;
        headerFile.getHeaderFileNameLength(headerFileNameLength);
        headerFile.getLoadPartNumberNameLength(loadPartNumberNameLength);

        size_t childSize = 0;
        headerFile.getFileSize(childSize);
        offset += childSize;
    }

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationRequestFile::serializeJSON(std::string &data)
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

    for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator it =
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

SerializableAuthenticationOperationResult
LoadAuthenticationRequestFile::deserializeJSON(std::string &data)
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
        LoadAuthenticationRequestHeaderFile headerFile;
        result = headerFile.deserializeJSON(data);
        free(headerFileData);
        if (result != SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK)
        {
            cJSON_Delete(root);
            return result;
        }
        std::string headerFileName;
        std::string loadPartNumberName;
        headerFile.getHeaderFileName(headerFileName);
        headerFile.getLoadPartNumberName(loadPartNumberName);
        headerFiles->emplace_back();
        headerFiles->back().setHeaderFileName(headerFileName);
        headerFiles->back().setLoadPartNumberName(loadPartNumberName);
    }
    cJSON_Delete(root);

    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationRequestFile::getFileSize(size_t &fileSize)
{
    FileAuthenticationOperationResult result = BaseAuthenticationFile::getFileSize(fileSize);
    if (result != FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK)
    {
        return result;
    }

    fileSize += sizeof(numberOfHeaderFiles);
    for (std::vector<LoadAuthenticationRequestHeaderFile>::iterator it =
             headerFiles->begin();
         it != headerFiles->end(); ++it)
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

LoadAuthenticationRequestHeaderFile::LoadAuthenticationRequestHeaderFile()
{
    std::memset(headerFileName, 0, sizeof(headerFileName));
    std::memset(loadPartNumberName, 0, sizeof(loadPartNumberName));
    headerFileNameLength = 0;
    loadPartNumberNameLength = 0;
}

LoadAuthenticationRequestHeaderFile::~LoadAuthenticationRequestHeaderFile()
{
}

FileAuthenticationOperationResult LoadAuthenticationRequestHeaderFile::setHeaderFileName(
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

FileAuthenticationOperationResult
LoadAuthenticationRequestHeaderFile::getHeaderFileName(std::string &headerFileName)
{
    headerFileName = this->headerFileName;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationRequestHeaderFile::setLoadPartNumberName(
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
LoadAuthenticationRequestHeaderFile::getLoadPartNumberName(std::string &loadPartNumberName)
{
    loadPartNumberName = this->loadPartNumberName;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult
LoadAuthenticationRequestHeaderFile::getHeaderFileNameLength(
    uint8_t &headerFileNameLength)
{
    headerFileNameLength = this->headerFileNameLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

FileAuthenticationOperationResult
LoadAuthenticationRequestHeaderFile::getLoadPartNumberNameLength(
    uint8_t &loadPartNumberNameLength)
{
    loadPartNumberNameLength = this->loadPartNumberNameLength;
    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationRequestHeaderFile::serialize(
    std::shared_ptr<std::vector<uint8_t>> &data)
{
    data->push_back(headerFileNameLength);
    data->insert(data->end(), headerFileName,
                 headerFileName + headerFileNameLength);
    data->push_back(loadPartNumberNameLength);
    data->insert(data->end(), loadPartNumberName,
                 loadPartNumberName + loadPartNumberNameLength);
    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationRequestHeaderFile::deserialize(
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
    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

SerializableAuthenticationOperationResult
LoadAuthenticationRequestHeaderFile::serializeJSON(std::string &data)
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
LoadAuthenticationRequestHeaderFile::deserializeJSON(std::string &data)
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

    cJSON_Delete(root);
    return SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK;
}

FileAuthenticationOperationResult LoadAuthenticationRequestHeaderFile::getFileSize(
    size_t &fileSize)
{
    fileSize = sizeof(headerFileNameLength) + headerFileNameLength +
               sizeof(loadPartNumberNameLength) + loadPartNumberNameLength;

    return FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK;
}