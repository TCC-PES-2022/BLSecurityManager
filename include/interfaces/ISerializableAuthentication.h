#ifndef ISERIALIZABLEAUTHENTICATION_H
#define ISERIALIZABLEAUTHENTICATION_H

/**
 * @brief Enum with possible return from interface functions.
 * Possible return values are:
 * - SERIALIZABLE_AUTHENTICATION_OK:                    Operation was successful.
 * - SERIALIZABLE_AUTHENTICATION_ERROR:                 Generic error.
 */
enum class SerializableAuthenticationOperationResult
{
        SERIALIZABLE_AUTHENTICATION_OK = 0,
        SERIALIZABLE_AUTHENTICATION_ERROR
};

class ISerializableAuthentication
{
public:
        /**
         * @brief Serialize object to binary data.
         *
         * @param[out] data serialized object.
         *
         * @return SERIALIZABLE_AUTHENTICATION_OK if success.
         * @return SERIALIZABLE_AUTHENTICATION_ERROR otherwise.
         */
        virtual SerializableAuthenticationOperationResult serialize(
            std::shared_ptr<std::vector<uint8_t>> &data) = 0;

        /**
         * @brief Serialize object to JSON string.
         *
         * @param[out] data serialized object.
         *
         * @return SERIALIZABLE_AUTHENTICATION_OK if success.
         * @return SERIALIZABLE_AUTHENTICATION_ERROR otherwise.
         */
        virtual SerializableAuthenticationOperationResult serializeJSON(
            std::string &data) = 0;

        /**
         * @brief Deserialize object to binary data.
         *
         * @param[in] data serialized object.
         *
         * @return SERIALIZABLE_AUTHENTICATION_OK if success.
         * @return SERIALIZABLE_AUTHENTICATION_ERROR otherwise.
         */
        virtual SerializableAuthenticationOperationResult deserialize(
            std::shared_ptr<std::vector<uint8_t>> &data) = 0;

        /**
         * @brief Deserialize object from JSON string.
         *
         * @param[in] data serialized object.
         *
         * @return SERIALIZABLE_AUTHENTICATION_OK if success.
         * @return SERIALIZABLE_AUTHENTICATION_ERROR otherwise.
         */
        virtual SerializableAuthenticationOperationResult deserializeJSON(
            std::string &data) = 0;
};

#endif // ISERIALIZABLEAUTHENTICATION_H