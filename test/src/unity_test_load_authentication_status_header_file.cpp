#include <gtest/gtest.h>

#include "LoadAuthenticationStatusFile.h"

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileSetFileName)
{
    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setHeaderFileName("TEST_FILE1.TEST"),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    std::string headerFileName = "";
    uint8_t headerFileNameLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getHeaderFileName(headerFileName),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getHeaderFileNameLength(headerFileNameLength),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(headerFileName, "TEST_FILE1.TEST");
    ASSERT_EQ(headerFileNameLength, 16);
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileSetLoadPartNumber)
{
    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadPartNumberName("TEST_PART_NUMBER1"),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    std::string loadPartNumberName = "";
    uint8_t loadPartNumberNameLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadPartNumberName(loadPartNumberName),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadPartNumberNameLength(loadPartNumberNameLength),
                FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadPartNumberName, "TEST_PART_NUMBER1");
    ASSERT_EQ(loadPartNumberNameLength, 18);
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileSetLoadRatio)
{
    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadRatio(42),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    uint32_t loadRatio = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadRatio(loadRatio),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadRatio, 42);
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileSetLoadStatus)
{
    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadStatus(0x4242),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    uint16_t loadStatus = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatus(loadStatus),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatus, 0x4242);
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileSetLoadStatusDescription)
{
    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadStatusDescription("TEST_STATUS_DESCRIPTION1"),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    std::string loadStatusDescription = "";
    uint8_t loadStatusDescriptionLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatusDescription(loadStatusDescription),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatusDescriptionLength(loadStatusDescriptionLength),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatusDescription, "TEST_STATUS_DESCRIPTION1");
    ASSERT_EQ(loadStatusDescriptionLength, 25);
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileSerialize)
{
    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setHeaderFileName("TEST_FILE1.TEST"),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadPartNumberName("TEST_PART_NUMBER1"),
                FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadRatio(42),
                FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadStatus(0x4242),
                FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadStatusDescription("TEST_STATUS_DESCRIPTION1"),
                FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    std::shared_ptr<std::vector<uint8_t>> data = std::make_shared<std::vector<uint8_t>>();
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.serialize(data),
              SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);
    ASSERT_EQ(data->size(), 67);
    ASSERT_EQ(data->at(0), 16);
    ASSERT_EQ(data->at(1), 'T');
    ASSERT_EQ(data->at(2), 'E');
    ASSERT_EQ(data->at(3), 'S');
    ASSERT_EQ(data->at(4), 'T');
    ASSERT_EQ(data->at(5), '_');
    ASSERT_EQ(data->at(6), 'F');
    ASSERT_EQ(data->at(7), 'I');
    ASSERT_EQ(data->at(8), 'L');
    ASSERT_EQ(data->at(9), 'E');
    ASSERT_EQ(data->at(10), '1');
    ASSERT_EQ(data->at(11), '.');
    ASSERT_EQ(data->at(12), 'T');
    ASSERT_EQ(data->at(13), 'E');
    ASSERT_EQ(data->at(14), 'S');
    ASSERT_EQ(data->at(15), 'T');
    ASSERT_EQ(data->at(16), '\0');
    ASSERT_EQ(data->at(17), 18);
    ASSERT_EQ(data->at(18), 'T');
    ASSERT_EQ(data->at(19), 'E');
    ASSERT_EQ(data->at(20), 'S');
    ASSERT_EQ(data->at(21), 'T');
    ASSERT_EQ(data->at(22), '_');
    ASSERT_EQ(data->at(23), 'P');
    ASSERT_EQ(data->at(24), 'A');
    ASSERT_EQ(data->at(25), 'R');
    ASSERT_EQ(data->at(26), 'T');
    ASSERT_EQ(data->at(27), '_');
    ASSERT_EQ(data->at(28), 'N');
    ASSERT_EQ(data->at(29), 'U');
    ASSERT_EQ(data->at(30), 'M');
    ASSERT_EQ(data->at(31), 'B');
    ASSERT_EQ(data->at(32), 'E');
    ASSERT_EQ(data->at(33), 'R');
    ASSERT_EQ(data->at(34), '1');
    ASSERT_EQ(data->at(35), '\0');
    ASSERT_EQ(data->at(36), 00);
    ASSERT_EQ(data->at(37), 00);
    ASSERT_EQ(data->at(38), 42);
    ASSERT_EQ(data->at(39), 0x42);
    ASSERT_EQ(data->at(40), 0x42);
    ASSERT_EQ(data->at(41), 25);
    ASSERT_EQ(data->at(42), 'T');
    ASSERT_EQ(data->at(43), 'E');
    ASSERT_EQ(data->at(44), 'S');
    ASSERT_EQ(data->at(45), 'T');
    ASSERT_EQ(data->at(46), '_');
    ASSERT_EQ(data->at(47), 'S');
    ASSERT_EQ(data->at(48), 'T');
    ASSERT_EQ(data->at(49), 'A');
    ASSERT_EQ(data->at(50), 'T');
    ASSERT_EQ(data->at(51), 'U');
    ASSERT_EQ(data->at(52), 'S');
    ASSERT_EQ(data->at(53), '_');
    ASSERT_EQ(data->at(54), 'D');
    ASSERT_EQ(data->at(55), 'E');
    ASSERT_EQ(data->at(56), 'S');
    ASSERT_EQ(data->at(57), 'C');
    ASSERT_EQ(data->at(58), 'R');
    ASSERT_EQ(data->at(59), 'I');
    ASSERT_EQ(data->at(60), 'P');
    ASSERT_EQ(data->at(61), 'T');
    ASSERT_EQ(data->at(62), 'I');
    ASSERT_EQ(data->at(63), 'O');
    ASSERT_EQ(data->at(64), 'N');
    ASSERT_EQ(data->at(65), '1');
    ASSERT_EQ(data->at(66), '\0');
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileDeserialize)
{
    std::shared_ptr<std::vector<uint8_t>> data = std::make_shared<std::vector<uint8_t>>();
    data->push_back(16);
    data->push_back('T');
    data->push_back('E');
    data->push_back('S');
    data->push_back('T');
    data->push_back('_');
    data->push_back('F');
    data->push_back('I');
    data->push_back('L');
    data->push_back('E');
    data->push_back('1');
    data->push_back('.');
    data->push_back('T');
    data->push_back('E');
    data->push_back('S');
    data->push_back('T');
    data->push_back('\0');
    data->push_back(18);
    data->push_back('T');
    data->push_back('E');
    data->push_back('S');
    data->push_back('T');
    data->push_back('_');
    data->push_back('P');
    data->push_back('A');
    data->push_back('R');
    data->push_back('T');
    data->push_back('_');
    data->push_back('N');
    data->push_back('U');
    data->push_back('M');
    data->push_back('B');
    data->push_back('E');
    data->push_back('R');
    data->push_back('1');
    data->push_back('\0');
    data->push_back(00);
    data->push_back(00);
    data->push_back(42);
    data->push_back(0x42);
    data->push_back(0x42);
    data->push_back(25);
    data->push_back('T');
    data->push_back('E');
    data->push_back('S');
    data->push_back('T');
    data->push_back('_');
    data->push_back('S');
    data->push_back('T');
    data->push_back('A');
    data->push_back('T');
    data->push_back('U');
    data->push_back('S');
    data->push_back('_');
    data->push_back('D');
    data->push_back('E');
    data->push_back('S');
    data->push_back('C');
    data->push_back('R');
    data->push_back('I');
    data->push_back('P');
    data->push_back('T');
    data->push_back('I');
    data->push_back('O');
    data->push_back('N');
    data->push_back('1');
    data->push_back('\0');

    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.deserialize(data),
              SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);

    uint8_t headerFileNameLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getHeaderFileNameLength(headerFileNameLength),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(headerFileNameLength, 16);

    std::string headerFileName;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getHeaderFileName(headerFileName),
            FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(headerFileName, "TEST_FILE1.TEST");

    uint8_t loadPartNumberNameLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadPartNumberNameLength(loadPartNumberNameLength),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadPartNumberNameLength, 18);

    std::string loadPartNumberName;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadPartNumberName(loadPartNumberName),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadPartNumberName, "TEST_PART_NUMBER1");

    uint32_t loadRatio = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadRatio(loadRatio),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadRatio, 42);

    uint16_t loadStatus = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatus(loadStatus),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatus, 0x4242);

    uint8_t loadStatusDescriptionLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatusDescriptionLength(loadStatusDescriptionLength),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatusDescriptionLength, 25);

    std::string loadStatusDescription;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatusDescription(loadStatusDescription),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatusDescription, "TEST_STATUS_DESCRIPTION1");
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileSerializeJSON)
{
    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setHeaderFileName("TEST_FILE1.TEST"),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadPartNumberName("TEST_PART_NUMBER1"),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadRatio(42),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadStatus(0x4242),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.setLoadStatusDescription("TEST_STATUS_DESCRIPTION1"),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);

    std::string data = std::string("");
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.serializeJSON(data),
              SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);

    ASSERT_EQ(data, "{"
                    "\"headerFileNameLength\":16,"
                    "\"headerFileName\":\"TEST_FILE1.TEST\","
                    "\"loadPartNumberNameLength\":18,"
                    "\"loadPartNumberName\":\"TEST_PART_NUMBER1\","
                    "\"loadRatio\":42,"
                    "\"loadStatus\":16962,"
                    "\"loadStatusDescriptionLength\":25,"
                    "\"loadStatusDescription\":\"TEST_STATUS_DESCRIPTION1\""
                    "}");
}

TEST(AuthenticationFilesTest, LoadAuthenticationStatusHeaderFileDeserializeJSON)
{
    std::string data = std::string("{"
                                   "\"headerFileNameLength\":16,"
                                   "\"headerFileName\":\"TEST_FILE1.TEST\","
                                   "\"loadPartNumberNameLength\":18,"
                                   "\"loadPartNumberName\":\"TEST_PART_NUMBER1\","
                                   "\"loadRatio\":42,"
                                   "\"loadStatus\":16962,"
                                   "\"loadStatusDescriptionLength\":25,"
                                   "\"loadStatusDescription\":\"TEST_STATUS_DESCRIPTION1\""
                                   "}");

    LoadAuthenticationStatusHeaderFile loadAuthenticationStatusHeaderFile;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.deserializeJSON(data),
              SerializableAuthenticationOperationResult::SERIALIZABLE_AUTHENTICATION_OK);

    uint8_t headerFileNameLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getHeaderFileNameLength(headerFileNameLength),
              FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(headerFileNameLength, 16);

    std::string headerFileName;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getHeaderFileName(headerFileName),
            FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(headerFileName, "TEST_FILE1.TEST");

    uint8_t loadPartNumberNameLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadPartNumberNameLength(loadPartNumberNameLength),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadPartNumberNameLength, 18);

    std::string loadPartNumberName;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadPartNumberName(loadPartNumberName),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadPartNumberName, "TEST_PART_NUMBER1");

    uint32_t loadRatio = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadRatio(loadRatio),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadRatio, 42);

    uint16_t loadStatus = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatus(loadStatus),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatus, 0x4242);

    uint8_t loadStatusDescriptionLength = 0;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatusDescriptionLength(loadStatusDescriptionLength),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatusDescriptionLength, 25);

    std::string loadStatusDescription;
    ASSERT_EQ(loadAuthenticationStatusHeaderFile.getLoadStatusDescription(loadStatusDescription),
        FileAuthenticationOperationResult::FILE_AUTHENTICATION_OPERATION_OK);
    ASSERT_EQ(loadStatusDescription, "TEST_STATUS_DESCRIPTION1");
}