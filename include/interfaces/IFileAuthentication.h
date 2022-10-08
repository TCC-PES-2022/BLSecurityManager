#ifndef FILEAUTHENTICATION_H
#define FILEAUTHENTICATION_H

#define AUTHENTICATION_VERSION "01"

/**
 * @brief Enum with possible return from interface functions.
 * Possible return values are:
 * - FILE_OPERATION_OK:                    Operation was successful.
 * - FILE_OPERATION_ERROR:                 Generic error.
 */
enum class FileOperationResult
{
    FILE_OPERATION_OK = 0,
    FILE_OPERATION_ERROR
};

class IFileAuthentication
{
protected:
    /**
     * @brief Get total file size in bytes. This will not return the size of
     * the entire Authentication file, but only the size of the class file.
     *
     * If you want to get the size of the entire Authentication file, you must
     * call the function getFileLength() from the BaseAuthenticationFile class.
     *
     * This method is intended to be used during file deserialization.
     *
     * @param[out] fileSize File size in bytes.
     *
     * @return FILE_OPERATION_OK if success.
     * @return FILE_OPERATION_ERROR otherwise.
     */
    virtual FileOperationResult getFileSize(size_t &fileSize) = 0;
};

#endif // FILEAUTHENTICATION_H
