#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/generic.h>
#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/datasource.hpp>
#include <string>
#include <utility>
#include <setjmp.h>

#define CF_CHECK_EQ(expr, res) if ( (expr) != (res) ) { goto end; }
#define CF_CHECK_NE(expr, res) if ( (expr) == (res) ) { goto end; }
#define CF_CHECK_GT(expr, res) if ( (expr) <= (res) ) { goto end; }
#define CF_CHECK_GTE(expr, res) if ( (expr) < (res) ) { goto end; }
#define CF_CHECK_LT(expr, res) if ( (expr) >= (res) ) { goto end; }
#define CF_CHECK_LTE(expr, res) if ( (expr) > (res) ) { goto end; }
#define CF_CHECK_TRUE(expr) if ( !(expr) ) { goto end; }
#define CF_CHECK_FALSE(expr) if ( (expr) ) { goto end; }
#define CF_ASSERT(expr, msg) if ( !(expr) ) { printf("Cryptofuzz assertion failure: %s\n", msg); ::abort(); }
#define CF_ASSERT_EQ(expr, res) if ( (expr) != (res) ) { printf("Cryptofuzz assertion failure\n"); ::abort(); }
#define CF_ASSERT_EQ_COND(expr, res, cond) \
    if ( (expr) != (res) ) { \
        if ( (cond) ) { \
            goto end; \
        } else { \
            printf("Cryptofuzz assertion failure\n"); ::abort(); \
        } \
    }
#define CF_UNREACHABLE() CF_ASSERT(0, "This code is supposed to be unreachable")
#define CF_NORET(expr) {static_assert(std::is_same<decltype(expr), void>::value, "void"); (expr);}

extern "C" {
    extern sigjmp_buf cryptofuzz_jmpbuf;
    extern unsigned char cryptofuzz_longjmp_triggered;
}

#define CF_INSTALL_JMP() do { \
    if( sigsetjmp(cryptofuzz_jmpbuf, 1) && (cryptofuzz_longjmp_triggered == 0) ) { \
        exit(-1); \
    } \
    if( cryptofuzz_longjmp_triggered == 1 ){ \
        goto end; \
    } \
} while(0); \

#define CF_RESTORE_JMP() do { \
    cryptofuzz_longjmp_triggered = 0; \
} while(0); \

// Macro to set each element in the tuple explicitly
#define ORDERED_EVAL_IMPL(tuple, index, arg) std::get<index>(tuple) = arg;

#define GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME

// Helper macros to generate a sequence of tuple assignment operations
#define ORDERED_EVAL_1(tuple, x1) ORDERED_EVAL_IMPL(tuple, 0, x1)
#define ORDERED_EVAL_2(tuple, x1, x2)                                          \
  ORDERED_EVAL_1(tuple, x1) ORDERED_EVAL_IMPL(tuple, 1, x2)
#define ORDERED_EVAL_3(tuple, x1, x2, x3)                                      \
  ORDERED_EVAL_2(tuple, x1, x2) ORDERED_EVAL_IMPL(tuple, 2, x3)
#define ORDERED_EVAL_4(tuple, x1, x2, x3, x4)                                  \
  ORDERED_EVAL_3(tuple, x1, x2, x3) ORDERED_EVAL_IMPL(tuple, 3, x4)
#define ORDERED_EVAL_5(tuple, x1, x2, x3, x4, x5)                              \
  ORDERED_EVAL_4(tuple, x1, x2, x3, x4) ORDERED_EVAL_IMPL(tuple, 4, x5)
#define ORDERED_EVAL_6(tuple, x1, x2, x3, x4, x5, x6)                          \
  ORDERED_EVAL_5(tuple, x1, x2, x3, x4, x5) ORDERED_EVAL_IMPL(tuple, 5, x6)
#define ORDERED_EVAL_7(tuple, x1, x2, x3, x4, x5, x6, x7)                      \
  ORDERED_EVAL_6(tuple, x1, x2, x3, x4, x5, x6) ORDERED_EVAL_IMPL(tuple, 6, x7)
#define ORDERED_EVAL_8(tuple, x1, x2, x3, x4, x5, x6, x7, x8)                  \
  ORDERED_EVAL_7(tuple, x1, x2, x3, x4, x5, x6, x7)                            \
  ORDERED_EVAL_IMPL(tuple, 7, x8)
#define ORDERED_EVAL_SELECT(...)                                               \
  GET_MACRO(__VA_ARGS__, ORDERED_EVAL_8, ORDERED_EVAL_7, ORDERED_EVAL_6,       \
            ORDERED_EVAL_5, ORDERED_EVAL_4, ORDERED_EVAL_3, ORDERED_EVAL_2,    \
            ORDERED_EVAL_1)

// Helper macros to generate a list of types from __VA_ARGS__
#define TYPEOF_1(x1) decltype(x1)
#define TYPEOF_2(x1, x2) decltype(x1), decltype(x2)
#define TYPEOF_3(x1, x2, x3) decltype(x1), decltype(x2), decltype(x3)
#define TYPEOF_4(x1, x2, x3, x4)                                               \
  decltype(x1), decltype(x2), decltype(x3), decltype(x4)
#define TYPEOF_5(x1, x2, x3, x4, x5)                                           \
  decltype(x1), decltype(x2), decltype(x3), decltype(x4), decltype(x5)
#define TYPEOF_6(x1, x2, x3, x4, x5, x6)                                       \
  decltype(x1), decltype(x2), decltype(x3), decltype(x4), decltype(x5),        \
      decltype(x6)
#define TYPEOF_7(x1, x2, x3, x4, x5, x6, x7)                                   \
  decltype(x1), decltype(x2), decltype(x3), decltype(x4), decltype(x5),        \
      decltype(x6), decltype(x7)
#define TYPEOF_8(x1, x2, x3, x4, x5, x6, x7, x8)                               \
  decltype(x1), decltype(x2), decltype(x3), decltype(x4), decltype(x5),        \
      decltype(x6), decltype(x7), decltype(x8)
#define TYPEOF(...)                                                            \
  GET_MACRO(__VA_ARGS__, TYPEOF_8, TYPEOF_7, TYPEOF_6, TYPEOF_5, TYPEOF_4,     \
            TYPEOF_3, TYPEOF_2, TYPEOF_1)                                      \
  (__VA_ARGS__)

// Return a tuple containing the evaluated arguments passed to the macro. This
// macro gurantees that the arguments are evaluated from left to right.
//
// Example:
//
// ```c++
// auto f = [](int a, int b, int c) { return a - b * c; };
// auto get = [] { static int i = 0; return ++i;};
// std::apply(f, CF_ORDERED_EVAL(get(), get(), get()));
// ```
//
// Calling `f(get(), get(), get())` directly would result in the evaluation
// order of the `get()` calls being undefined, i.e. the order might differ
// across compilers (see https://en.cppreference.com/w/cpp/language/eval_order).
//
// In this example `CF_ORDERED_EVAL(get(), get(), get())` expands to:
//
// ```c++
// [] {
//   std::tuple<int, int, int> t;
//   std::get<0>(t) = get();
//   std::get<1>(t) = get();
//   std::get<2>(t) = get();
//   return t;
// }()
// ```
#define CF_ORDERED_EVAL(...)                                                   \
  [&] {                                                                        \
    auto t = std::tuple<TYPEOF(__VA_ARGS__)>();                                \
    ORDERED_EVAL_SELECT(__VA_ARGS__)(t, __VA_ARGS__) return t;                 \
  }()

namespace cryptofuzz {
namespace util {

using Multipart = std::vector< std::pair<const uint8_t*, size_t> >;
const uint8_t* ToInPlace(fuzzing::datasource::Datasource& ds, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize);
Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, const uint8_t* in, const size_t inSize);
Multipart CipherInputTransform(fuzzing::datasource::Datasource& ds, component::SymmetricCipherType cipherType, uint8_t* out, const size_t outSize, const uint8_t* in, const size_t inSize);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const std::vector<uint8_t>& buffer, const size_t blocksize = 0);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const Buffer& buffer, const size_t blocksize = 0);
Multipart ToParts(fuzzing::datasource::Datasource& ds, const uint8_t* data, const size_t size, const size_t blocksize = 0);
Multipart ToEqualParts(const Buffer& buffer, const size_t partSize);
Multipart ToEqualParts(const uint8_t* data, const size_t size, const size_t partSize);
std::vector<uint8_t> Pkcs7Pad(std::vector<uint8_t> in, const size_t blocksize);
std::optional<std::vector<uint8_t>> Pkcs7Unpad(std::vector<uint8_t> in, const size_t blocksize);
std::string ToString(const Buffer& buffer);
std::string ToString(const bool val);
std::string ToString(const component::Ciphertext& val);
std::string ToString(const component::ECC_PublicKey& val);
std::string ToString(const component::ECC_KeyPair& val);
std::string ToString(const component::ECCSI_Signature& val);
std::string ToString(const component::ECDSA_Signature& val);
std::string ToString(const component::Bignum& val);
std::string ToString(const component::G2& val);
std::string ToString(const component::BLS_Signature& val);
std::string ToString(const component::BLS_BatchSignature& val);
std::string ToString(const component::BLS_KeyPair& val);
std::string ToString(const component::Fp12& val);
std::string ToString(const component::DSA_Parameters& val);
std::string ToString(const component::DSA_Signature& val);
std::string ToString(const component::Key3& val);
nlohmann::json ToJSON(const Buffer& buffer);
nlohmann::json ToJSON(const bool val);
nlohmann::json ToJSON(const component::Ciphertext& val);
nlohmann::json ToJSON(const component::ECC_PublicKey& val);
nlohmann::json ToJSON(const component::ECC_KeyPair& val);
nlohmann::json ToJSON(const component::ECCSI_Signature& val);
nlohmann::json ToJSON(const component::ECDSA_Signature& val);
nlohmann::json ToJSON(const component::Bignum& val);
nlohmann::json ToJSON(const component::G2& val);
nlohmann::json ToJSON(const component::BLS_Signature& val);
nlohmann::json ToJSON(const component::BLS_BatchSignature& val);
nlohmann::json ToJSON(const component::BLS_KeyPair& val);
nlohmann::json ToJSON(const component::Fp12& val);
nlohmann::json ToJSON(const component::DSA_Parameters& val);
nlohmann::json ToJSON(const component::DSA_Signature& val);
nlohmann::json ToJSON(const component::Key3& val);
void SetGlobalDs(fuzzing::datasource::Datasource* ds);
void UnsetGlobalDs(void);
uint8_t* GetNullPtr(fuzzing::datasource::Datasource* ds = nullptr);
uint8_t* malloc(const size_t n);
uint8_t* realloc(void* ptr, const size_t n);
void free(void* ptr);
bool HaveSSE42(void);
void abort(const std::vector<std::string> components);
std::string HexToDec(std::string s);
std::string DecToHex(std::string s, const std::optional<size_t> padTo = std::nullopt);
std::vector<uint8_t> HexToBin(const std::string s);
std::optional<std::vector<uint8_t>> DecToBin(const std::string s, std::optional<size_t> size = std::nullopt);
std::string BinToHex(const uint8_t* data, const size_t size);
std::string BinToHex(const std::vector<uint8_t> data);
std::string BinToDec(const uint8_t* data, const size_t size);
std::string BinToDec(const std::vector<uint8_t> data);
std::optional<std::vector<uint8_t>> ToDER(const std::string A, const std::string B);
std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::string s);
std::optional<std::pair<std::string, std::string>> SignatureFromDER(const std::vector<uint8_t> data);
std::optional<std::pair<std::string, std::string>> PubkeyFromASN1(const uint64_t curveType, const std::string s);
std::optional<std::pair<std::string, std::string>> PubkeyFromASN1(const uint64_t curveType, const std::vector<uint8_t> data);
std::string SHA1(const std::vector<uint8_t> data);
void HintBignum(const std::string bn);
void HintBignumPow2(size_t maxSize = 4000);
void HintBignumInt(void);
void HintBignumOpt(const std::optional<std::string> bn);
std::vector<uint8_t> Append(const std::vector<uint8_t> A, const std::vector<uint8_t> B);
std::vector<uint8_t> RemoveLeadingZeroes(std::vector<uint8_t> v);
std::vector<uint8_t> AddLeadingZeroes(fuzzing::datasource::Datasource& ds, const std::vector<uint8_t>& v);
void AdjustECDSASignature(const uint64_t curveType, component::Bignum& s);
std::string Find_ECC_Y(const std::string& x, const std::string& a, const std::string& b, const std::string& p, const std::string& o, const bool addOrder);
std::array<std::string, 3> ToRandomProjective(fuzzing::datasource::Datasource& ds, const std::string& x, const std::string& y, const uint64_t curveType, const bool jacobian = true, const bool inRange = false);
namespace Ethereum_ModExp {
    uint64_t Gas(std::vector<uint8_t> input, const bool eip2565);
    std::vector<uint8_t> ToInput(
            const component::Bignum& base,
            const component::Bignum& exp,
            const component::Bignum& mod);
}
void MemorySanitizerUnpoison(const void* data, const size_t size);

} /* namespace util */
} /* namespace cryptofuzz */
