#include "cmd_options.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>

// A struct for test parameters for better readability
struct OptionsTestParam {
  std::string test_name;
  std::vector<std::string> args;
  bool expected_result;
};

class TestProgrammOptionsParametrized
    : public ::testing::TestWithParam<OptionsTestParam> {
protected:
  // This SetUp correctly handles argument lifetimes.
  void SetUp() override {
    const auto &arguments = GetParam().args;

    // Store strings to ensure their lifetime for the duration of the test
    arg_storage_.push_back("test_program"); // argv[0] is the program name
    for (const auto &arg : arguments) {
      arg_storage_.push_back(arg);
    }

    // Create the C-style argv array of pointers
    for (const auto &s : arg_storage_) {
      argv_.push_back(const_cast<char *>(s.c_str()));
    }
    argc_ = argv_.size();
  }

protected:
  int argc_;
  std::vector<char *> argv_;
  std::vector<std::string> arg_storage_;
  CryptoGuard::ProgramOptions options;
};

TEST_P(TestProgrammOptionsParametrized, ParseArguments) {
  bool expected = GetParam().expected_result;
  EXPECT_EQ(options.Parse(argc_, argv_.data()), expected);
}

INSTANTIATE_TEST_SUITE_P(
    CmdOptionsTests, TestProgrammOptionsParametrized,
    ::testing::Values(
        OptionsTestParam{"EmptyArgs", {}, false},
        OptionsTestParam{"Help", {"--help"}, false},
        OptionsTestParam{"ShortNameArgsValid",
                         {"-c", "checksum", "-i", "input.txt", "-o",
                          "output.txt", "-p", "123"},
                         true},
        OptionsTestParam{"FullNameArgsValid",
                         {"--command", "checksum", "--input", "input.txt",
                          "--output", "output.txt", "--password", "123"},
                         true},
        OptionsTestParam{"EncryptArgsValid",
                         {"-c", "encrypt", "-i", "in.txt", "-o", "out.txt",
                          "-p", "123"},
                         true},
        OptionsTestParam{"InvalidArgs",
                         {"--commandqweqw", "checksum", "--inputwer",
                          "input.txt"},
                         false},
        OptionsTestParam{"EmptyValuesForRequiredArgs",
                         {"--command", "", "--input", ""}, false},
        OptionsTestParam{"InvalidCommandValue",
                         {"-c", "chechsum", "-i", "input.txt"}, false},
        OptionsTestParam{"EncryptMissingOutput",
                         {"-c", "encrypt", "-i", "in.txt"}, false},
        OptionsTestParam{"DecryptMissingInput",
                         {"-c", "decrypt", "-o", "out.txt"}, false}),
    [](const ::testing::TestParamInfo<OptionsTestParam> &info) {
      return info.param.test_name;
    });