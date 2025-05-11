#include "crypto_guard_ctx.h"
#include <bits/chrono.h>
#include <cstddef>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <istream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#define ERROR_CRYPTO_GUARD_CTX(function_name)                                  \
  throw std::runtime_error(std::format(                                        \
      "{0}: {1}", #function_name, ERR_error_string(ERR_get_error(), nullptr)))

namespace CryptoGuard {

using CryptoContextPtr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) {
                      EVP_CIPHER_CTX_free(ctx);
                    })>;
using MDContextPtr =
    std::unique_ptr<EVP_MD_CTX,
                    decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

class CryptoGuardCtx::Impl {
public:
  Impl() { OpenSSL_add_all_algorithms(); }

  void Encrypt(std::iostream &inStream, std::iostream &outStream,
               std::string_view password) {

    CheckIOStream(inStream);
    CheckIOStream(outStream);

    input_ = {std::istreambuf_iterator<std::string::value_type>(inStream),
              std::istreambuf_iterator<std::string::value_type>()};

    CreateChiperParamsFromPassword(password);

    params_.encrypt = 1; // 1 - encrypt
    ExecuteCryptoOperation();
    for (const char c : outBuf_) {
      outStream << c;
    }
  }

  void Decrypt(std::iostream &inStream, std::iostream &outStream,
               std::string_view password) {

    CheckIOStream(inStream);
    CheckIOStream(outStream);

    input_ = {std::istreambuf_iterator<std::string::value_type>(inStream),
              std::istreambuf_iterator<std::string::value_type>()};

    CreateChiperParamsFromPassword(password);

    params_.encrypt = 0; // 0 - decrypt
    ExecuteCryptoOperation();
    for (const char c : outBuf_) {
      outStream << c;
    }
  }

  std::string CalculateChecksum(std::iostream &inStream) {

    CheckIOStream(inStream);
    input_ = {std::istreambuf_iterator<std::string::value_type>(inStream),
              std::istreambuf_iterator<std::string::value_type>()};

    // Инициализируем контекст
    MDContextPtr md_cntx(EVP_MD_CTX_new());
    if (!md_cntx.get()) {
      ERROR_CRYPTO_GUARD_CTX(EVP_MD_CTX_new);
    }

    if (!EVP_DigestInit_ex(md_cntx.get(), EVP_sha256(), nullptr)) {
      ERROR_CRYPTO_GUARD_CTX(EVP_DigestInit_ex);
    }

    if (!EVP_DigestUpdate(md_cntx.get(), input_.c_str(), input_.size())) {
      ERROR_CRYPTO_GUARD_CTX(EVP_DigestUpdate);
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (!EVP_DigestFinal_ex(md_cntx.get(), hash, &lengthOfHash)) {
      ERROR_CRYPTO_GUARD_CTX(EVP_DigestFinal_ex);
    }

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
  }

  ~Impl() { EVP_cleanup(); }

private:
  struct AesCipherParams {
    static const size_t KEY_SIZE = 32;            // AES-256 key size
    static const size_t IV_SIZE = 16;             // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc(); // Cipher algorithm

    int encrypt; // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key; // Encryption key
    std::array<unsigned char, IV_SIZE> iv;   // Initialization vector
  };

  void CreateChiperParamsFromPassword(std::string_view password) {

    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4',
                                                   '5', '6', '7', '8'};

    int result = EVP_BytesToKey(
        params_.cipher, EVP_sha256(), salt.data(),
        reinterpret_cast<const unsigned char *>(password.data()),
        password.size(), 1, params_.key.data(), params_.iv.data());

    if (result == 0) {
      ERROR_CRYPTO_GUARD_CTX(CreateChiperParamsFromPassword);
    }
  }

  void ExecuteCryptoOperation() {

    // Утечка для проверки GTest
    // std::string *srt_ptr = new std::string{"sfdsf"};
    // std::format("{0}", *srt_ptr);

    // Инициализируем криптоконтекст
    CryptoContextPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) {
      ERROR_CRYPTO_GUARD_CTX(EVP_CIPHER_CTX_new);
    }

    // Инициализируем cipher
    if (!EVP_CipherInit_ex2(ctx.get(), params_.cipher, params_.key.data(),
                            params_.iv.data(), params_.encrypt, NULL)) {
      ERROR_CRYPTO_GUARD_CTX(EVP_CipherInit_ex2);
    }

    // Заполняем входной буфер
    inBuf_.resize(input_.size());
    for (size_t i = 0; i < input_.size(); ++i) {
      inBuf_[i] = input_[i];
    }

    outBuf_.clear();
    outBuf_.resize(input_.size() + EVP_MAX_BLOCK_LENGTH);

    // Выполняем операцию
    if (!EVP_CipherUpdate(ctx.get(), outBuf_.data(), &totalLen_, inBuf_.data(),
                          inBuf_.size())) {
      ERROR_CRYPTO_GUARD_CTX(EVP_CipherUpdate);
    }

    // Заканчиваем работу с cipher
    if (!EVP_CipherFinal_ex(ctx.get(), outBuf_.data() + totalLen_, &outLen_)) {
      ERROR_CRYPTO_GUARD_CTX(EVP_CipherFinal_ex);
    }

    totalLen_ += outLen_;
    outBuf_.resize(totalLen_);
  }

  void CheckIOStream(std::iostream &stream) {
    if (stream.fail()) {
      throw std::runtime_error("Failure open input/output stream");
    }
  }

  AesCipherParams params_;
  std::vector<unsigned char> outBuf_;
  std::vector<unsigned char> inBuf_;
  int outLen_, totalLen_;
  std::string input_;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {};

CryptoGuardCtx::~CryptoGuardCtx() {};

void CryptoGuardCtx::EncryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  GetPImpl()->Encrypt(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream,
                                 std::iostream &outStream,
                                 std::string_view password) {
  GetPImpl()->Decrypt(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
  return GetPImpl()->CalculateChecksum(inStream);
}

const CryptoGuardCtx::Impl *CryptoGuardCtx::GetPImpl() const {
  return pImpl_.get();
}

CryptoGuardCtx::Impl *CryptoGuardCtx::GetPImpl() { return pImpl_.get(); }

} // namespace CryptoGuard
