#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>

using namespace std::literals;

// --- Базовая фикстура с общими элементами ---
class TestCryptoGuardCtxFixture : public ::testing::Test {
protected:
  // Вспомогательная функция для чтения stringstream в строку
  static std::string StreamToString(std::stringstream &ss) {
    // Сбрасываем позицию чтения в начало перед чтением
    ss.seekg(0, std::ios::beg);
    return {std::istreambuf_iterator<char>(ss),
            std::istreambuf_iterator<char>()};
  }

  CryptoGuard::CryptoGuardCtx cryptoCtx;
};

// --- Параметрический тест для ошибок ввода-вывода ---

enum class OperationType { Encrypt, Decrypt, Checksum };
enum class FailingStream { Input, Output };

struct IoFailureTestParam {
  std::string test_name;
  OperationType operation;
  FailingStream failing_stream;
};

class CryptoGuardCtxIoFailureTest
    : public TestCryptoGuardCtxFixture,
      public ::testing::WithParamInterface<IoFailureTestParam> {};

TEST_P(CryptoGuardCtxIoFailureTest, ThrowsOnStreamFailure) {
  auto param = GetParam();
  std::stringstream input("some data");
  std::stringstream output;

  if (param.failing_stream == FailingStream::Input) {
    input.setstate(std::ios::failbit);
  } else { // Output
    if (param.operation != OperationType::Checksum) {
      output.setstate(std::ios::failbit);
    } else {
      GTEST_SKIP()
          << "Checksum operation does not use an output stream in this context.";
    }
  }

  switch (param.operation) {
  case OperationType::Encrypt:
    ASSERT_THROW(cryptoCtx.EncryptFile(input, output, "pass"),
                 std::runtime_error);
    break;
  case OperationType::Decrypt:
    ASSERT_THROW(cryptoCtx.DecryptFile(input, output, "pass"),
                 std::runtime_error);
    break;
  case OperationType::Checksum:
    ASSERT_THROW(cryptoCtx.CalculateChecksum(input), std::runtime_error);
    break;
  }
}

INSTANTIATE_TEST_SUITE_P(
    IoFailures, CryptoGuardCtxIoFailureTest,
    ::testing::Values(
        IoFailureTestParam{"EncryptFailsOnBadInput", OperationType::Encrypt,
                           FailingStream::Input},
        IoFailureTestParam{"EncryptFailsOnBadOutput", OperationType::Encrypt,
                           FailingStream::Output},
        IoFailureTestParam{"DecryptFailsOnBadInput", OperationType::Decrypt,
                           FailingStream::Input},
        IoFailureTestParam{"DecryptFailsOnBadOutput", OperationType::Decrypt,
                           FailingStream::Output},
        IoFailureTestParam{"ChecksumFailsOnBadInput", OperationType::Checksum,
                           FailingStream::Input}),
    [](const ::testing::TestParamInfo<IoFailureTestParam> &info) {
      return info.param.test_name;
    });

// --- Параметрический тест для вычисления контрольной суммы ---

struct ChecksumTestParam {
  std::string test_name;
  std::string input_data;
  std::string expected_checksum;
};

class CryptoGuardCtxChecksumTest
    : public TestCryptoGuardCtxFixture,
      public ::testing::WithParamInterface<ChecksumTestParam> {};

TEST_P(CryptoGuardCtxChecksumTest, CalculatesCorrectChecksum) {
  auto param = GetParam();
  std::stringstream input(param.input_data);
  EXPECT_EQ(cryptoCtx.CalculateChecksum(input), param.expected_checksum);
}

INSTANTIATE_TEST_SUITE_P(
    ChecksumTests, CryptoGuardCtxChecksumTest,
    ::testing::Values(
        ChecksumTestParam{
            "ChecksumFor_12345", "12345",
            "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"},
        ChecksumTestParam{
            "ChecksumFor_abcde", "abcde",
            "36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c"},
        ChecksumTestParam{
            "ChecksumFor_Symbols", "$'][?",
            "68c322cb326a7cf2bbf40fe30e652b76859381200c15342180e037215d4d06c0"},
        ChecksumTestParam{
            "ChecksumFor_DataWithNulls", std::string("data\0with\0nulls", 15),
            "48c61ce9358d7b8e3c40405430dbf42516b00f9a8a9de891f3b577eac9ed0519"},
        ChecksumTestParam{
            "ChecksumFor_EmptyString", "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
    [](const ::testing::TestParamInfo<ChecksumTestParam> &info) {
      return info.param.test_name;
    });

// --- Тест на переиспользование контекста ---
TEST_F(TestCryptoGuardCtxFixture, ContextIsReusableForMultipleOperations) {
  // Первая операция
  {
    std::stringstream input("Первое сообщение"), encrypted, decrypted;
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(input, encrypted, "pass1"));
    ASSERT_NO_THROW(cryptoCtx.DecryptFile(encrypted, decrypted, "pass1"));
    EXPECT_EQ(StreamToString(decrypted), "Первое сообщение");
  }

  // Вторая, другая операция на том же контексте
  {
    std::stringstream input("Второе сообщение"), encrypted, decrypted;
    ASSERT_NO_THROW(cryptoCtx.EncryptFile(input, encrypted, "pass2"));
    ASSERT_NO_THROW(cryptoCtx.DecryptFile(encrypted, decrypted, "pass2"));
    EXPECT_EQ(StreamToString(decrypted), "Второе сообщение");
  }
}

// --- Параметрический тест для цикла шифрования/дешифрования ---

struct EncryptDecryptTestParam {
  std::string test_name;
  std::string original_text;
  std::string encrypt_pass;
  std::string decrypt_pass;
  bool should_succeed;
};

class CryptoGuardCtxEncryptDecryptTest
    : public TestCryptoGuardCtxFixture,
      public ::testing::WithParamInterface<EncryptDecryptTestParam> {};

TEST_P(CryptoGuardCtxEncryptDecryptTest, FullCycle) {
  auto param = GetParam();

  // 1. Шифрование
  std::stringstream encrypt_input(param.original_text);
  std::stringstream encrypted_output;
  cryptoCtx.EncryptFile(encrypt_input, encrypted_output, param.encrypt_pass);
  std::string encrypted_data = StreamToString(encrypted_output);

  // 2. Дешифрование
  std::stringstream decrypt_input(encrypted_data);
  std::stringstream decrypted_output;

  if (param.should_succeed) {
    // Проверяем также консистентность контрольной суммы
    std::stringstream original_checksum_input(param.original_text);
    std::string original_checksum =
        cryptoCtx.CalculateChecksum(original_checksum_input);

    ASSERT_NO_THROW(cryptoCtx.DecryptFile(decrypt_input, decrypted_output,
                                          param.decrypt_pass));
    std::string decrypted_text = StreamToString(decrypted_output);

    std::stringstream decrypted_checksum_input(decrypted_text);
    std::string decrypted_checksum =
        cryptoCtx.CalculateChecksum(decrypted_checksum_input);

    EXPECT_EQ(decrypted_text, param.original_text);
    EXPECT_EQ(decrypted_checksum, original_checksum);
  } else {
    ASSERT_THROW(cryptoCtx.DecryptFile(decrypt_input, decrypted_output,
                                       param.decrypt_pass),
                 std::runtime_error);
  }
}

INSTANTIATE_TEST_SUITE_P(
    EncryptDecryptCycles, CryptoGuardCtxEncryptDecryptTest,
    ::testing::Values(
        EncryptDecryptTestParam{"SuccessfulCycle", "Hello world!", "123", "123",
                                true},
        EncryptDecryptTestParam{"SuccessfulCycleWithComplexPassword",
                                "Some other secret message.", "!@#$%^&*()_+",
                                "!@#$%^&*()_+", true},
        EncryptDecryptTestParam{"FailedCycleWithWrongPassword",
                                "This will fail.", "correct_pass",
                                "wrong_pass", false},
        EncryptDecryptTestParam{"SuccessfulCycleWithEmptyPassword",
                                "data with empty password", "", "", true},
        EncryptDecryptTestParam{"SuccessfulCycleWithEmptyString", "",
                                "password", "password", true},
        EncryptDecryptTestParam{"SuccessfulCycleWithDataContainingNulls",
                                std::string("data\0with\0nulls", 15),
                                "password", "password", true},
        EncryptDecryptTestParam{"SuccessfulCycleWithLargeData",
                                std::string(10000, 'A'), "long_data_password",
                                "long_data_password", true}),
    [](const ::testing::TestParamInfo<EncryptDecryptTestParam> &info) {
      return info.param.test_name;
    });