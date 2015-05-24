// Making a base64 parser with Spirit X3
// Inspired by Meredith Patterson's videos on making one with Hammer:
// https://www.youtube.com/playlist?list=PLMAs0n8Mjs9o2I4KZ14gQr2osDsd3YPoT

#include <string>
#include <iostream>
#include <cstdint>
#include <map>

#include <boost/spirit/include/support_istream_iterator.hpp>
#include <boost/spirit/home/x3.hpp>
#include <boost/spirit/home/x3/extensions/repeat.hpp>

#include <boost/fusion/functional/invocation/invoke.hpp>

#define BOOST_TEST_MODULE base64 parser tests
#include <boost/test/included/unit_test.hpp>

// Our AST is simple: it's a string.  Sub-parser results will get concatenated.

namespace parser {

namespace x3    = boost::spirit::x3;
namespace ascii = boost::spirit::x3::ascii;

using x3::lit;
using x3::lexeme;
using x3::repeat;

using ascii::char_;
using ascii::alnum;

// define tags, types, and names for rules
struct bsfdig      {};
struct bsfdig_4bit {};   // chars whose lower four bits are zero
struct bsfdig_2bit {};   // chars whose lowest six bits are zero
struct base64_3    {};   // produces three decoded characters
struct base64_2    {};   // "      "  two  "                "
struct base64_1    {};   // etc.
struct base64      {};   // produces the entire string

template<typename Tag> using char_rule_t = x3::rule<Tag, uint8_t>;
template<typename Tag> using str_rule_t = x3::rule<Tag, std::string>;

typedef char_rule_t<bsfdig>       bsfdig_type;
typedef char_rule_t<bsfdig_4bit>  bsfdig_4bit_type;
typedef char_rule_t<bsfdig_2bit>  bsfdig_2bit_type;
typedef str_rule_t<base64_3>      base64_3_type;
typedef str_rule_t<base64_2>      base64_2_type;
typedef str_rule_t<base64_1>      base64_1_type;
typedef str_rule_t<base64>        base64_type;

bsfdig_type      const bsfdig      = "bsfdig";
bsfdig_4bit_type const bsfdig_4bit = "bsfdig_4bit";
bsfdig_2bit_type const bsfdig_2bit = "bsfdig_2bit";
base64_3_type    const base64_3    = "base64_3";
base64_2_type    const base64_2    = "base64_2";
base64_1_type    const base64_1    = "base64_1";
base64_type      const base64      = "base64";

// helper for semantic action (digit translation)
// the 6-bit values 0 through 63 are mapped to A-Za-z0-9+/
// We need the reverse map for decoding
// consider symtab here!!
struct decode_byte {
    template<typename Context>
    void operator()(Context const& ctx) {
        using namespace boost;
        uint8_t& result = spirit::x3::_val(ctx);
        char          c = get<char>(spirit::x3::_attr(ctx));

        if(c >= 0x41 && c <= 0x5A) // A-Z
            result = c - 0x41;
        else if(c >= 0x61 && c <= 0x7A) // a-z
            result = c - 0x61 + 26;
        else if(c >= 0x30 && c <= 0x39) // 0-9
            result = c - 0x30 + 52;
        else if(c == '+')
            result = 62;
        else if(c == '/')
            result = 63;
        else
            throw std::runtime_error(std::string("input out of range: |") + c + "|");
    }
};

// This variadic function template handles between 2 and 4 6-bit quantities
// decoded by the function above, turning them into a 1-3 byte string
template<typename ... Hextets>
std::string decode_bytes_str(Hextets... h) {
    // In C++17 we may be able to do this with a parameter pack "fold"
    // Doing this all at runtime for now by storing the parameters in an array
    std::array<uint8_t, sizeof...(h)> h_arr = {h...};

    // Store the 6b quantities as a bitstring within a 32b word
    uint32_t bytes = 0;
    for (uint8_t v : h_arr) {
        bytes <<= 6;
        bytes |= v;
    }

    std::size_t const bits = 6*sizeof...(h);
    bytes >>= (bits % 8);   // align (cut off excess bits)

    // Pull the bits back out a byte at a time
    std::string result;
    for (std::size_t i = 0; i < sizeof...(h)-1; ++i) {
        result += std::string(1, 0xff & (bytes >> (sizeof...(h) - i - 2)*8));
    }
    return result;
}

// This forwarding function is a trick suggested by Agustin Berge (K-ballo)
// It gives a single "name" for the fusion::invoke to deal with
// If I try to call decode_bytes_str directly I get an unresolved overload error...
auto decode_fwd =  [](auto&&... args){
    return decode_bytes_str(std::forward<decltype(args)>(args)...);
};

// This semantic action is a polymorphic lambda that expands into versions for
// each of the three context types (one for each rule) it sees:
auto handle_chars  = 
    [](auto & ctx) {
        using namespace boost;
        std::string& result = spirit::x3::_val(ctx);
        result += fusion::invoke(decode_fwd, spirit::x3::_attr(ctx));
    } ;

// Just translating Meredith's grammar here:
auto const bsfdig_def      = (alnum | '+' | '/')[decode_byte()] ;
auto const bsfdig_4bit_def = char_("AEIMQUYcgkosw048")[decode_byte()] ;
auto const bsfdig_2bit_def = char_("AQgw")[decode_byte()] ;
auto const base64_3_def    = (bsfdig >> bsfdig >> bsfdig >> bsfdig)[handle_chars] ;
auto const base64_2_def    = (bsfdig >> bsfdig >> bsfdig_4bit >> '=')[handle_chars] ;
auto const base64_1_def    = (bsfdig >> bsfdig_2bit >> '=' >> '=')[handle_chars] ;
auto const base64_def      = *base64_3 >> -(base64_2 | base64_1) ;
// the "document" rule isn't necessary since we will use a Spirit "skip parser"
// to deal with whitespace

BOOST_SPIRIT_DEFINE(bsfdig, bsfdig_4bit, bsfdig_2bit, base64_3, base64_2, base64_1, base64)

}

// Per Meredith's suggestion, applying test vectors from RFC4648:

void check_parse(std::string test, std::string expected) {
    typedef boost::spirit::istream_iterator iter_t;
    std::istringstream ss(test);
    ss.unsetf(std::ios::skipws);
    iter_t beg(ss), end;
    std::string decoded;
    using parser::base64;
    using boost::spirit::x3::ascii::space;
    // parsing passes
    BOOST_CHECK( phrase_parse(beg, end, base64, space, decoded) );
    // result is as expected
    BOOST_CHECK_EQUAL( expected, decoded );
    // all input consumed
    BOOST_CHECK_EQUAL( beg, end );
}

BOOST_TEST_DONT_PRINT_LOG_VALUE(boost::spirit::istream_iterator);

BOOST_AUTO_TEST_CASE( basic ) {

    check_parse("", "");
    check_parse("Zg==", "f");
    check_parse("Zm8=", "fo");
    check_parse("Zm9v", "foo");
    check_parse("Zm9vYg==", "foob");
    check_parse("Zm9vYmE=", "fooba");
    check_parse("Zm9vYmFy", "foobar");
}
