#include "archive/archive_manager.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <zip.h>

namespace archive {

static bool create_zipcrypto_with_crc_check(const std::string& archive_path,
                                              const std::string& password,
                                              const std::string& source_file_path) {
    std::string cmd = "zip -P '" + password + "' -j '" + archive_path
                      + "' '" + source_file_path + "' 2>/dev/null";
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

bool ArchiveManager::create_test_archive(const std::string& archive_path,
                                          const std::string& password,
                                          const std::string& source_file_path,
                                          EncryptionType encryption) {

    if (encryption == EncryptionType::ZIP_CRYPTO) {
        return create_zipcrypto_with_crc_check(archive_path, password,
                                                source_file_path);
    }

    int error_code = 0;
    zip_t* archive = zip_open(archive_path.c_str(),
                               ZIP_CREATE | ZIP_TRUNCATE,
                               &error_code);
    if (!archive) {
        std::cerr << "Failed to create archive: " << archive_path
                  << " (error " << error_code << ")" << std::endl;
        return false;
    }

    std::ifstream src(source_file_path, std::ios::binary | std::ios::ate);
    if (!src.is_open()) {
        std::cerr << "Failed to open source file: " << source_file_path << std::endl;
        zip_close(archive);
        return false;
    }

    auto file_size = src.tellg();
    src.seekg(0, std::ios::beg);

    std::vector<char> buffer(file_size);
    src.read(buffer.data(), file_size);
    src.close();

    zip_source_t* source = zip_source_buffer(archive, buffer.data(), file_size, 0);
    if (!source) {
        std::cerr << "Failed to create zip source buffer" << std::endl;
        zip_close(archive);
        return false;
    }

    std::string entry_name = source_file_path.substr(source_file_path.find_last_of('/') + 1);

    zip_int64_t idx = zip_file_add(archive, entry_name.c_str(), source,
                                    ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE);
    if (idx < 0) {
        std::cerr << "Failed to add file to archive: "
                  << zip_strerror(archive) << std::endl;
        zip_source_free(source);
        zip_close(archive);
        return false;
    }

    if (encryption != EncryptionType::NONE) {
        int enc_method = ZIP_EM_TRAD_PKWARE;
        switch (encryption) {
            case EncryptionType::AES_128: enc_method = ZIP_EM_AES_128; break;
            case EncryptionType::AES_192: enc_method = ZIP_EM_AES_192; break;
            case EncryptionType::AES_256: enc_method = ZIP_EM_AES_256; break;
            default: enc_method = ZIP_EM_TRAD_PKWARE; break;
        }

        if (zip_file_set_encryption(archive, idx, enc_method,
                                     password.c_str()) < 0) {
            std::cerr << "Failed to set encryption: " << zip_strerror(archive) << std::endl;
            zip_close(archive);
            return false;
        }
    }

    if (zip_close(archive) < 0) {
        std::cerr << "Failed to close archive: " << zip_strerror(archive) << std::endl;
        return false;
    }

    return true;
}

bool ArchiveManager::verify_password(const std::string& archive_path,
                                      const std::string& password) {
    int error_code = 0;
    zip_t* archive = zip_open(archive_path.c_str(), ZIP_RDONLY, &error_code);
    if (!archive) {
        return false;
    }

    zip_int64_t num_entries = zip_get_num_entries(archive, 0);
    if (num_entries <= 0) {
        zip_close(archive);
        return false;
    }

    const char* entry_name = zip_get_name(archive, 0, 0);
    if (!entry_name) {
        zip_close(archive);
        return false;
    }

    const char* pwd = password.c_str();

    zip_file_t* file = zip_fopen_encrypted(archive, entry_name, 0, pwd);
    if (!file) {
        zip_close(archive);
        return false;
    }

    char buf[4096];
    zip_int64_t total = 0;
    zip_int64_t n;
    while ((n = zip_fread(file, buf, sizeof(buf))) > 0) {
        total += n;
    }
    zip_fclose(file);
    zip_close(archive);

    return total > 0 && n == 0;
}

std::vector<ArchiveInfo> ArchiveManager::create_test_suite(
    const std::string& output_dir,
    const std::string& source_file_path) {

    std::vector<ArchiveInfo> archives;

    struct TestCase {
        std::string name;
        std::string password;
        std::string charset_name;
        EncryptionType encryption;
    };

    std::vector<TestCase> test_cases = {
        {"numeric_4.zip",        "4821",   "digits",    EncryptionType::ZIP_CRYPTO},
        {"numeric_5.zip",        "83920",  "digits",    EncryptionType::ZIP_CRYPTO},
        {"lowercase_4.zip",      "hjkd",   "lowercase", EncryptionType::ZIP_CRYPTO},
        {"lowercase_5.zip",      "qwert",  "lowercase", EncryptionType::ZIP_CRYPTO},
        {"alphanum_4.zip",       "a1b2",   "alphanum",  EncryptionType::ZIP_CRYPTO},
        {"alphanum_5.zip",       "a1b2c",  "alphanum",  EncryptionType::ZIP_CRYPTO},
        {"aes256_4.zip",         "x9yz",   "alphanum",  EncryptionType::AES_256},
        {"aes256_5.zip",         "x9yz2",  "alphanum",  EncryptionType::AES_256},
    };

    for (const auto& tc : test_cases) {
        std::string archive_path = output_dir + "/" + tc.name;

        if (create_test_archive(archive_path, tc.password,
                                 source_file_path, tc.encryption)) {
            std::ifstream f(archive_path, std::ios::binary | std::ios::ate);
            int64_t archive_size = f.tellg();
            f.close();

            std::ifstream src_file(source_file_path, std::ios::binary | std::ios::ate);
            int64_t original_size = src_file.tellg();
            src_file.close();

            time_t now = time(nullptr);
            char date_buf[32];
            strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S",
                     localtime(&now));

            ArchiveInfo info;
            info.name = tc.name;
            info.path = archive_path;
            info.password = tc.password;
            info.password_length = tc.password.length();
            info.charset_name = tc.charset_name;
            info.encryption = tc.encryption;
            info.archive_size_bytes = archive_size;
            info.original_size_bytes = original_size;
            info.creation_date = date_buf;

            archives.push_back(info);
        }
    }

    return archives;
}

std::vector<ArchiveInfo> ArchiveManager::create_benchmark_suite(
    const std::string& output_dir,
    const std::string& source_file_path) {

    std::vector<ArchiveInfo> archives;

    struct BenchEntry {
        std::string prefix;
        std::string charset_name;
        EncryptionType encryption;
        std::vector<std::string> passwords;
    };

    std::vector<BenchEntry> entries = {
        {"zip_digits",    "digits",    EncryptionType::ZIP_CRYPTO,
         {"7", "39", "482", "4821", "83920"}},
        {"zip_lowercase", "lowercase", EncryptionType::ZIP_CRYPTO,
         {"a", "hx", "hjk", "hjkd", "qwert"}},
        {"zip_alphanum",  "alphanum",  EncryptionType::ZIP_CRYPTO,
         {"a", "a1", "a1b", "a1b2", "a1b2c"}},
        {"aes_alphanum",  "alphanum",  EncryptionType::AES_256,
         {"x", "x9", "x9y", "x9yz", "x9yz2"}},
    };

    for (const auto& entry : entries) {
        for (size_t i = 0; i < entry.passwords.size(); ++i) {
            size_t len = i + 1;
            std::string name = entry.prefix + "_L" + std::to_string(len) + ".zip";
            std::string archive_path = output_dir + "/" + name;

            if (create_test_archive(archive_path, entry.passwords[i],
                                     source_file_path, entry.encryption)) {
                std::ifstream f(archive_path, std::ios::binary | std::ios::ate);
                int64_t archive_size = f.tellg();
                f.close();

                time_t now = time(nullptr);
                char date_buf[32];
                strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S",
                         localtime(&now));

                ArchiveInfo info;
                info.name = name;
                info.path = archive_path;
                info.password = entry.passwords[i];
                info.password_length = len;
                info.charset_name = entry.charset_name;
                info.encryption = entry.encryption;
                info.archive_size_bytes = archive_size;
                info.original_size_bytes = 0;
                info.creation_date = date_buf;
                archives.push_back(info);
            }
        }
    }

    return archives;
}

} // namespace archive
