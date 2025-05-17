#include "cmd_options.h"
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <cctype>
#include <exception>
#include <format>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

  desc_.add_options()("help", "information of available options")(
      "command,c", po::value<COMMAND_TYPE>(&command_)->required(),
      "command - [encrypt], [decrypt] or [checksum]")(
      "input,i", po::value<std::string>(&inputFile_)->required(),
      "path to the input file")(
      "output,o", po::value<std::string>(&outputFile_),
      "the path to the file where the result will be saved")(
      "password,p", po::value<std::string>(&password_),
      "password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {

  try {

    po::variables_map var_map;
    po::store(po::parse_command_line(argc, argv, desc_), var_map);

    if (var_map.count("help")) {
      desc_.print(std::cout);
      return false;
    }

    var_map.notify();

    if (command_ == COMMAND_TYPE::DECRYPT ||
        command_ == COMMAND_TYPE::ENCRYPT) {
          
          std::string error_message{};

          if(inputFile_.empty()){
            error_message += "the option '--input' is required but missing\n";
          }

          if(outputFile_.empty()){
            error_message += "the option '--output' is required but missing\n";
          }

          if(!error_message.empty()){
            throw std::runtime_error(error_message);
          }

    }

    return true;

  } catch (std::exception &e) {

    std::print(std::cerr, "\x1B[31m{0}\033[0m\t\t\n", e.what());
    // desc_.print(std::cout);
    return false;
  }
}

std::istream &operator>>(std::istream &input,
                         ProgramOptions::COMMAND_TYPE &command) {
  std::string com_str;
  input >> com_str;
  transform(com_str.begin(), com_str.end(), com_str.begin(), ::tolower);
  if (com_str == "encrypt") {
    command = ProgramOptions::COMMAND_TYPE::ENCRYPT;
  } else if (com_str == "decrypt") {
    command = ProgramOptions::COMMAND_TYPE::DECRYPT;
  } else if (com_str == "checksum") {
    command = ProgramOptions::COMMAND_TYPE::CHECKSUM;
  }
  return input;
}

} // namespace CryptoGuard
