#include "memory_leaks.h"
#include <gtest/gtest.h>
#include <jemalloc/jemalloc.h>
#include <print>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  // Тестирование утечек памяти
  ::testing::UnitTest::GetInstance()->listeners().Append(
      new testing::MemoryLeaksDetector());
  return RUN_ALL_TESTS();
}
