#include <gtest/gtest.h>

#include "InitializationAuthenticationFile.h"

TEST(AuthenticationFilesTest, InitializationFileSerialization)
{
    InitializationAuthenticationFile initializationFile("TEST_FILE.TEST", "A4");

    size_t fileSize = 0;
    initializationFile.getFileSize(fileSize);
    printf("File size: %d\n", fileSize);

    initializationFile.setOperationAcceptanceStatusCode(0x0001);
    initializationFile.setStatusDescription("Test file");
    std::vector<uint8_t> cryptographicKey = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    initializationFile.setCryptographicKey(cryptographicKey);

    std::shared_ptr<std::vector<uint8_t>>
        data = std::make_shared<std::vector<uint8_t>>();
    ASSERT_EQ(initializationFile.serialize(data), SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);
    ASSERT_EQ(data->size(), 37);
    ASSERT_EQ(data->at(0), 0);
    ASSERT_EQ(data->at(1), 0);
    ASSERT_EQ(data->at(2), 0);
    ASSERT_EQ(data->at(3), 37);
    ASSERT_EQ(data->at(4), 'A');
    ASSERT_EQ(data->at(5), '4');
    ASSERT_EQ(data->at(6), 0);
    ASSERT_EQ(data->at(7), 1);
    ASSERT_EQ(data->at(8), 0x00);
    ASSERT_EQ(data->at(9), 0x10);
    ASSERT_EQ(data->at(10), 0x01);
    ASSERT_EQ(data->at(11), 0x02);
    ASSERT_EQ(data->at(12), 0x03);
    ASSERT_EQ(data->at(13), 0x04);
    ASSERT_EQ(data->at(14), 0x05);
    ASSERT_EQ(data->at(15), 0x06);
    ASSERT_EQ(data->at(16), 0x07);
    ASSERT_EQ(data->at(17), 0x08);
    ASSERT_EQ(data->at(18), 0x09);
    ASSERT_EQ(data->at(19), 0x0A);
    ASSERT_EQ(data->at(20), 0x0B);
    ASSERT_EQ(data->at(21), 0x0C);
    ASSERT_EQ(data->at(22), 0x0D);
    ASSERT_EQ(data->at(23), 0x0E);
    ASSERT_EQ(data->at(24), 0x0F);
    ASSERT_EQ(data->at(25), 0x10);
    ASSERT_EQ(data->at(26), 0x0A);
    ASSERT_EQ(data->at(27), 'T');
    ASSERT_EQ(data->at(28), 'e');
    ASSERT_EQ(data->at(29), 's');
    ASSERT_EQ(data->at(30), 't');
    ASSERT_EQ(data->at(31), ' ');
    ASSERT_EQ(data->at(32), 'f');
    ASSERT_EQ(data->at(33), 'i');
    ASSERT_EQ(data->at(34), 'l');
    ASSERT_EQ(data->at(35), 'e');
    ASSERT_EQ(data->at(36), '\0');
}

// TODO: Add public key field
TEST(AuthenticationFilesTest, DISABLED_InitializationFileSerializationDescriptionOverflow)
{
    InitializationAuthenticationFile initializationFile("TEST_FILE.TEST", "A4");
    initializationFile.setOperationAcceptanceStatusCode(0x0001);

    // Max description length is 255 bytes
    std::string description(1024, 'a');
    initializationFile.setStatusDescription(description);

    std::shared_ptr<std::vector<uint8_t>> data = std::make_shared<std::vector<uint8_t>>();
    ASSERT_EQ(initializationFile.serialize(data), SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);
    EXPECT_EQ(data->size(), 264);
    EXPECT_EQ(data->at(0), 0);
    EXPECT_EQ(data->at(1), 0);
    EXPECT_EQ(data->at(2), 0x01);
    EXPECT_EQ(data->at(3), 0x08);
    EXPECT_EQ(data->at(4), 'A');
    EXPECT_EQ(data->at(5), '4');
    EXPECT_EQ(data->at(6), 0);
    EXPECT_EQ(data->at(7), 1);
    EXPECT_EQ(data->at(8), 0xFF);
    for (int i = 9; i < 262; i++)
    {
        EXPECT_EQ(data->at(i), 'a');
    }
    EXPECT_EQ(data->at(263), '\0');
}

TEST(AuthenticationFilesTest, DISABLED_InitializationFileCryptographicKeyOverflow)
{
    FAIL() << "Not implemented";
}

TEST(AuthenticationFilesTest, InitializationFileDeserialization)
{
    InitializationAuthenticationFile initializationFile;
    std::shared_ptr<std::vector<uint8_t>> data = std::make_shared<std::vector<uint8_t>>();
    data->push_back(0);
    data->push_back(0);
    data->push_back(0);
    data->push_back(37);
    data->push_back('A');
    data->push_back('4');
    data->push_back(0);
    data->push_back(1);
    data->push_back(0x00);
    data->push_back(0x10);
    data->push_back(0x01);
    data->push_back(0x02);
    data->push_back(0x03);
    data->push_back(0x04);
    data->push_back(0x05);
    data->push_back(0x06);
    data->push_back(0x07);
    data->push_back(0x08);
    data->push_back(0x09);
    data->push_back(0x0A);
    data->push_back(0x0B);
    data->push_back(0x0C);
    data->push_back(0x0D);
    data->push_back(0x0E);
    data->push_back(0x0F);
    data->push_back(0x10);
    data->push_back(0x0A);
    data->push_back('T');
    data->push_back('e');
    data->push_back('s');
    data->push_back('t');
    data->push_back(' ');
    data->push_back('f');
    data->push_back('i');
    data->push_back('l');
    data->push_back('e');
    data->push_back('\0');
    ASSERT_EQ(initializationFile.deserialize(data), SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);

    uint32_t fileLength = 0;
    ASSERT_EQ(initializationFile.getFileLength(fileLength), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    std::string protocolVersion = "";
    ASSERT_EQ(initializationFile.getProtocolVersion(protocolVersion), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    uint16_t operationAcceptanceStatusCode = 0;
    ASSERT_EQ(initializationFile.getOperationAcceptanceStatusCode(operationAcceptanceStatusCode), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    uint16_t cryptographicKeylength = 0;
    ASSERT_EQ(initializationFile.getCryptographicKeyLength(cryptographicKeylength), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    std::vector<uint8_t> cryptographicKey;
    ASSERT_EQ(initializationFile.getCryptographicKey(cryptographicKey), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    uint8_t statusDescriptionLength = 0;
    ASSERT_EQ(initializationFile.getStatusDescriptionLength(statusDescriptionLength), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    std::string statusDescription = "";
    ASSERT_EQ(initializationFile.getStatusDescription(statusDescription), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    ASSERT_EQ(fileLength, 37);
    ASSERT_EQ(protocolVersion, std::string("A4"));
    ASSERT_EQ(operationAcceptanceStatusCode, 0x0001);
    ASSERT_EQ(cryptographicKeylength, 0x0010);
    ASSERT_EQ(cryptographicKey.size(), 16);

    // TODO: Do we have an assert for vector?
    ASSERT_EQ(cryptographicKey.at(0), 0x01);
    ASSERT_EQ(cryptographicKey.at(1), 0x02);
    ASSERT_EQ(cryptographicKey.at(2), 0x03);
    ASSERT_EQ(cryptographicKey.at(3), 0x04);
    ASSERT_EQ(cryptographicKey.at(4), 0x05);
    ASSERT_EQ(cryptographicKey.at(5), 0x06);
    ASSERT_EQ(cryptographicKey.at(6), 0x07);
    ASSERT_EQ(cryptographicKey.at(7), 0x08);
    ASSERT_EQ(cryptographicKey.at(8), 0x09);
    ASSERT_EQ(cryptographicKey.at(9), 0x0A);
    ASSERT_EQ(cryptographicKey.at(10), 0x0B);
    ASSERT_EQ(cryptographicKey.at(11), 0x0C);
    ASSERT_EQ(cryptographicKey.at(12), 0x0D);
    ASSERT_EQ(cryptographicKey.at(13), 0x0E);
    ASSERT_EQ(cryptographicKey.at(14), 0x0F);
    ASSERT_EQ(cryptographicKey.at(15), 0x10);

    ASSERT_EQ(statusDescriptionLength, 0x0A);
    ASSERT_EQ(statusDescription, std::string("Test file"));
}

TEST(AuthenticationFilesTest, InitializationFileSerializationJSON)
{
    InitializationAuthenticationFile initializationFile("TEST_FILE.TEST", "A4");
    initializationFile.setOperationAcceptanceStatusCode(0x0001);
    std::vector<uint8_t> cryptographicKey = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    initializationFile.setCryptographicKey(cryptographicKey);
    initializationFile.setStatusDescription("Test file");

    std::string data("");
    ASSERT_EQ(initializationFile.serializeJSON(data), SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);
    ASSERT_EQ(data, "{"
                    "\"fileName\":\"TEST_FILE.TEST\","
                    "\"fileLength\":37,"
                    "\"protocolVersion\":\"A4\","
                    "\"operationAcceptanceStatusCode\":1,"
                    "\"cryptographicKeyLength\":16,"
                    "\"cryptographicKey\":\"0102030405060708090a0b0c0d0e0f10\","
                    "\"statusDescriptionLength\":10,"
                    "\"statusDescription\":\"Test file\""
                    "}");
}

TEST(AuthenticationFilesTest, InitializationFileDeserializationJSON)
{
    InitializationAuthenticationFile initializationFile;
    std::string data("{"
                     "\"fileName\":\"TEST_FILE.TEST\","
                     "\"fileLength\":37,"
                     "\"protocolVersion\":\"A4\","
                     "\"operationAcceptanceStatusCode\":1,"
                     "\"cryptographicKeyLength\":16,"
                     "\"cryptographicKey\":\"0102030405060708090a0b0c0d0e0f10\","
                     "\"statusDescriptionLength\":10,"
                     "\"statusDescription\":\"Test file\""
                     "}");
    ASSERT_EQ(initializationFile.deserializeJSON(data), SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);

    uint32_t fileLength = 0;
    ASSERT_EQ(initializationFile.getFileLength(fileLength), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    std::string protocolVersion = "";
    ASSERT_EQ(initializationFile.getProtocolVersion(protocolVersion), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    uint16_t operationAcceptanceStatusCode = 0;
    ASSERT_EQ(initializationFile.getOperationAcceptanceStatusCode(operationAcceptanceStatusCode), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    uint16_t cryptographicKeylength = 0;
    ASSERT_EQ(initializationFile.getCryptographicKeyLength(cryptographicKeylength), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    std::vector<uint8_t> cryptographicKey;
    ASSERT_EQ(initializationFile.getCryptographicKey(cryptographicKey), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    uint8_t statusDescriptionLength = 0;
    ASSERT_EQ(initializationFile.getStatusDescriptionLength(statusDescriptionLength), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    std::string statusDescription = "";
    ASSERT_EQ(initializationFile.getStatusDescription(statusDescription), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    ASSERT_EQ(fileLength, 37);
    ASSERT_EQ(protocolVersion, std::string("A4"));
    ASSERT_EQ(operationAcceptanceStatusCode, 0x0001);
    ASSERT_EQ(cryptographicKeylength, 0x0010);
    ASSERT_EQ(cryptographicKey.size(), 16);

    // TODO: Do we have an assert for vector?
    ASSERT_EQ(cryptographicKey.at(0), 0x01);
    ASSERT_EQ(cryptographicKey.at(1), 0x02);
    ASSERT_EQ(cryptographicKey.at(2), 0x03);
    ASSERT_EQ(cryptographicKey.at(3), 0x04);
    ASSERT_EQ(cryptographicKey.at(4), 0x05);
    ASSERT_EQ(cryptographicKey.at(5), 0x06);
    ASSERT_EQ(cryptographicKey.at(6), 0x07);
    ASSERT_EQ(cryptographicKey.at(7), 0x08);
    ASSERT_EQ(cryptographicKey.at(8), 0x09);
    ASSERT_EQ(cryptographicKey.at(9), 0x0A);
    ASSERT_EQ(cryptographicKey.at(10), 0x0B);
    ASSERT_EQ(cryptographicKey.at(11), 0x0C);
    ASSERT_EQ(cryptographicKey.at(12), 0x0D);
    ASSERT_EQ(cryptographicKey.at(13), 0x0E);
    ASSERT_EQ(cryptographicKey.at(14), 0x0F);
    ASSERT_EQ(cryptographicKey.at(15), 0x10);

    ASSERT_EQ(statusDescriptionLength, 0x0A);
    ASSERT_EQ(statusDescription, std::string("Test file"));
}

TEST(AuthenticationFilesTest, InitializationFileFileName)
{
    BaseAuthenticationFile baseFile("TEST_FILE.TEST");
    std::string fileName = "";
    ASSERT_EQ(baseFile.getFileName(fileName), FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(fileName, "TEST_FILE.TEST");
}