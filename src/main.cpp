#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {

  try {
    CryptoGuard::ProgramOptions options;

    if (!options.Parse(argc, argv)) {
      return 1;
    }

    CryptoGuard::CryptoGuardCtx cryptoCtx;

    using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

    // Открываем входящий и исходящий файлы
    std::fstream input_file(options.GetInputFile(), std::ios::in);
    if (!input_file.is_open()) {
      throw std::runtime_error(
          std::format("Ошибка открытия файла {0}", options.GetInputFile()));
    }
    std::fstream output_file(options.GetOutputFile(), std::ios::out);

    // В зависимости от команды вызываем нужный метод
    switch (options.GetCommand()) {
    case COMMAND_TYPE::ENCRYPT:
      cryptoCtx.EncryptFile(input_file, output_file, options.GetPassword());
      std::print("File encoded successfully in {}\n", options.GetOutputFile());
      break;

    case COMMAND_TYPE::DECRYPT:
      cryptoCtx.DecryptFile(input_file, output_file, options.GetPassword());
      std::print("File decoded successfully in {}\n", options.GetOutputFile());
      break;

    case COMMAND_TYPE::CHECKSUM:
      if (!options.GetOutputFile().empty()) {
        output_file << cryptoCtx.CalculateChecksum(input_file);
        std::print("Checksum saved in file: {}\n", options.GetOutputFile());
      } else {
        std::print("{0}\n", cryptoCtx.CalculateChecksum(input_file));
      }

      break;

    default:
      throw std::runtime_error{"Unsupported command"};
    }

  } catch (const std::exception &e) {
    std::print(std::cerr, "Error: {}\n", e.what());
    return 1;
  }

  return 0;
}
