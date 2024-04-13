#pragma warning(disable : 4996)
#include <iostream>
#include <fstream>
//https://github.com/google/benchmark/pull/1470
#define BENCHMARK_STATIC_DEFINE
#pragma comment(lib, "shlwapi.lib")
#include <benchmark/benchmark.h>
#include <openssl/sha.h>
#include <immintrin.h>
#include "micro_hash256.h"

std::shared_ptr<char[]> data;
std::streampos fsize;
std::shared_ptr<char[]> read_file_to_buffer(const char* filename, std::streampos& file_size);
std::streampos fileSize(const char* filePath);

void print_sha256_hash(const uint8_t hash[32]) {
  for (int i = 0; i < 32; ++i) {
    printf("%02x", hash[i]);
  }
  printf("\n");
}

void OsCryptAPI(benchmark::State& state) {
  uint8_t hash_bytes[32]{};
  for (auto _ : state) {
    sha256Buffer((uint8_t*)data.get(), fsize, hash_bytes, 32);
  }
  //print_sha256_hash(hash_bytes);
}
void OpensslCryptAPI(benchmark::State& state) {
  uint8_t hash_bytes[32]{};
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  for (auto _ : state) {
    SHA256_Update(&sha256, data.get(), fsize);
    SHA256_Final(hash_bytes, &sha256);
  }
  //print_sha256_hash(hash_bytes);

}
BENCHMARK(OsCryptAPI)->Unit(benchmark::TimeUnit::kSecond)->Iterations(1);
BENCHMARK(OpensslCryptAPI)->Unit(benchmark::TimeUnit::kSecond)->Iterations(1);

int main(int argc,char*argv[])
{
  data = read_file_to_buffer(R"(C:\Program Files\Google\Chrome\Application\123.0.6312.107\chrome.dll)",fsize);

  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}

std::shared_ptr<char[]> read_file_to_buffer(const char* filename,
                                           std::streampos& file_size) {
  std::ifstream ifile(filename, std::ios::binary | std::ios::in);
  if (!ifile.is_open()) {
    return NULL;
  }
  auto fsize = fileSize(filename);
  if (fsize == 0) return NULL;
  file_size = fsize;

  auto p = std::shared_ptr<char[]>(new char[fsize]);
  ifile.read(p.get(), fsize);

  return p;
}

std::streampos fileSize(const char* filePath) {
  std::streampos fsize = 0;
  std::ifstream file(filePath, std::ios::binary);

  fsize = file.tellg();
  file.seekg(0, std::ios::end);
  fsize = file.tellg() - fsize;
  file.close();

  return fsize;
}
