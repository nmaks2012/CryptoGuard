#include "cmd_options.h"
#include <gtest/gtest.h>
#include <linux/limits.h>

class TestProgrammOptionsFixtures : public ::testing::Test {
protected:
  // Создает массив аргументов командной строки.
  void SetUp(std::vector<std::string> &&arguments) {
    argv.emplace_back(
        nullptr); // Первый аргумент название самого, вызываемого приложения.
    for (const auto &arg : arguments) {
      argv.emplace_back((char *)arg.data());
    }
    argc = argv.size();
  }

protected:
  int argc;
  std::vector<char *> argv;
  CryptoGuard::ProgramOptions options;
};

TEST_F(TestProgrammOptionsFixtures, EmptyArgs) {
  SetUp({});
  EXPECT_FALSE(options.Parse(argc, argv.data()));
}

TEST_F(TestProgrammOptionsFixtures, Help) {
  SetUp({"--help"});
  EXPECT_FALSE(options.Parse(argc, argv.data()));
}

TEST_F(TestProgrammOptionsFixtures, ShortNameArgs) {
  SetUp({"-c", "chechsum", "-i", "input.txt", "-o", "output.txt", "-p", "123"});
  EXPECT_TRUE(options.Parse(argc, argv.data()));
}

TEST_F(TestProgrammOptionsFixtures, FullNameArgs) {
  SetUp({"--command", "chechsum", "--input", "input.txt", "--output",
         "output.txt", "--password", "123"});
  EXPECT_TRUE(options.Parse(argc, argv.data()));
}

TEST_F(TestProgrammOptionsFixtures, InvalidArgs) {
  SetUp({"--commandqweqw", "chechsum", "--inputwer", "input.txt", "--outputsd",
         "output.txt", "--passwordss", "123"});
  EXPECT_FALSE(options.Parse(argc, argv.data()));
}

TEST_F(TestProgrammOptionsFixtures, EmptyValuesArgs) {
  SetUp({"--command", "", "--input", "", "--output", "", "--password", ""});
  EXPECT_FALSE(options.Parse(argc, argv.data()));
}