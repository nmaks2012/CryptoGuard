#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <iterator>
#include <linux/limits.h>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace std::literals;

class TestCryptoGuardCtxFixture : public ::testing::Test {
protected:
  std::stringstream input;
  std::string inputStr = "Hello world!";
  std::stringstream output;
  std::string outputStr;
  CryptoGuard::CryptoGuardCtx cryptoCtx;
  void Encrypt(std::string &in, std::string &&pass) {
    input << in;
    cryptoCtx.EncryptFile(input, output, pass);
    // Выводим результат в строку
    OutputToStr();
  }
  void Decrypt(std::string &in, std::string &&pass) {
    input << in;
    cryptoCtx.DecryptFile(input, output, pass);
    // Выводим результат в строку
    OutputToStr();
  }
  void Checksum(std::string &in) {
    input << in;
    cryptoCtx.CalculateChecksum(input);
    OutputToStr();
  }
  void OutputToStr() {
    outputStr = {std::istreambuf_iterator<std::string::value_type>(output),
                 std::istreambuf_iterator<std::string::value_type>()};
  }
};

TEST_F(TestCryptoGuardCtxFixture, EncryptFailedInput) {
  input.setstate(std::ios::failbit);
  ASSERT_THROW(Encrypt(inputStr, "123"), std::runtime_error::exception);
}

TEST_F(TestCryptoGuardCtxFixture, EncryptFailedOutput) {
  output.setstate(std::ios::failbit);
  ASSERT_THROW(Encrypt(inputStr, "123"), std::runtime_error::exception);
}

TEST_F(TestCryptoGuardCtxFixture, DecryptFailedInput) {
  input.setstate(std::ios::failbit);
  ASSERT_THROW(Decrypt(inputStr, "123"), std::runtime_error::exception);
}

TEST_F(TestCryptoGuardCtxFixture, DecryptFailedOutput) {
  output.setstate(std::ios::failbit);
  ASSERT_THROW(Decrypt(inputStr, "123"), std::runtime_error::exception);
}

TEST_F(TestCryptoGuardCtxFixture, EncryptDecrypt) {

  Encrypt(inputStr, "123");
  std::string result_encrypt = outputStr;
  Decrypt(result_encrypt, "123");
  std::string result_decrypt = outputStr;
  EXPECT_EQ(inputStr, result_decrypt);
}

TEST_F(TestCryptoGuardCtxFixture, DecryptInvalidPass) {

  std::string inputStr = "Hello world!";
  Encrypt(inputStr, "123");
  std::string result_encrypt = outputStr;
  ASSERT_THROW(Decrypt(result_encrypt, "1"), std::runtime_error::exception);
}

TEST_F(TestCryptoGuardCtxFixture, ChecksumInvalidInput) {
  std::string inputStr = "123";
  input.setstate(std::ios::failbit);
  ASSERT_THROW(Checksum(inputStr), std::runtime_error::exception);
}

TEST_F(TestCryptoGuardCtxFixture, Checksum) {
  input << "12345";
  EXPECT_EQ(cryptoCtx.CalculateChecksum(input),
            "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5");
  input << "abcde";
  EXPECT_EQ(cryptoCtx.CalculateChecksum(input),
            "36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c");
  input << "$'][?";
  EXPECT_EQ(cryptoCtx.CalculateChecksum(input),
            "68c322cb326a7cf2bbf40fe30e652b76859381200c15342180e037215d4d06c0");
}

TEST_F(TestCryptoGuardCtxFixture, EncryptDecryptHashCheck) {

  // Encrypt
  Encrypt(inputStr, "123");
  std::string result_encrypt = outputStr;
  // Calculate Hash befor
  input << inputStr;
  std::string hash_befor = cryptoCtx.CalculateChecksum(input);
  // Decrypt
  Decrypt(result_encrypt, "123");
  std::string result_decrypt = outputStr;
  // Calculate Hash befor
  input << result_decrypt;
  std::string hash_after = cryptoCtx.CalculateChecksum(input);
  // check input/output string
  EXPECT_EQ(inputStr, result_decrypt);
  // check before/after hash
  EXPECT_EQ(hash_befor, hash_after);
}