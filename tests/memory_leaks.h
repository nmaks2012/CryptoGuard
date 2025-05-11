#include <cstddef>
#include <cstdlib>
#include <format>
#include <gtest/gtest.h>
#include <jemalloc/jemalloc.h>
#include <new>
#include <print>

static std::size_t numAllocs{0};
static std::size_t numDeallocs{0};

static std::size_t numArrayAllocs{0};
static std::size_t numArrayDeallocs{0};

namespace testing {
class MemoryLeaksDetector : public EmptyTestEventListener {
  virtual void OnTestStart(const TestInfo &) {
    numAllocs = 0;
    numDeallocs = 0;
    numArrayAllocs = 0;
    numArrayDeallocs = 0;
  }
  virtual void OnTestEnd(const TestInfo &test_info) {
    if (numAllocs != numDeallocs) {
      FAIL() << std::format(
          "\x1B[31mMemory Leak: numAllocs - {0}, numDeallocs - {1}\033[0m\n",
          numAllocs, numDeallocs);
    }
    if (numArrayAllocs != numArrayDeallocs) {
      FAIL() << std::format("\x1B[31mMemory Leak: numArrayAllocs - {0}, "
                            "numArrayDeallocs - {1}\033[0m\n",
                            numArrayAllocs, numArrayDeallocs);
    }
  }
};
} // namespace testing

void *operator new(std::size_t sz) {
  void *ptr = malloc(sz);

  if (!ptr || sz == 0) {
    throw std::bad_alloc();
  }
  ++numAllocs;
  return ptr;
}

void operator delete(void *ptr) noexcept {
  ++numDeallocs;
  free(ptr);
}
void operator delete(void *ptr, std::size_t sz) noexcept {
  ++numDeallocs;
  free(ptr);
}

void *operator new[](std::size_t sz) {
  void *ptr = malloc(sz);

  if (!ptr || sz == 0) {
    throw std::bad_alloc();
  }
  ++numArrayAllocs;
  return ptr;
}

void operator delete[](void *ptr) noexcept {
  ++numArrayDeallocs;
  free(ptr);
}
void operator delete[](void *ptr, std::size_t sz) noexcept {
  ++numArrayDeallocs;
  free(ptr);
}
