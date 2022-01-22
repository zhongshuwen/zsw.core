#include <boost/test/unit_test.hpp>
#include <eosio/testing/tester.hpp>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/wast_to_wasm.hpp>

#include <Runtime/Runtime.h>

#include <fc/variant_object.hpp>
#include "contracts.hpp"
#include "test_symbol.hpp"

using namespace eosio::testing;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;

using mvo = fc::mutable_variant_object;

class zsw_perms_tester : public tester {
public:
   zsw_perms_tester() {
      create_accounts( { N(zsw.perms), N(eosio.stake), N(eosio.ram), N(eosio.ramfee), N(alice), N(bob), N(carol) } );
      produce_block();

      auto trace = base_tester::push_action(config::system_account_name, N(setpriv),
                                            config::system_account_name,  mutable_variant_object()
                                            ("account", "zsw.perms")
                                            ("is_priv", 1)
      );

      set_code( N(zsw.perms), contracts::zsw_perms_wasm() );
      set_abi( N(zsw.perms), contracts::zsw_perms_abi().data() );

      produce_blocks();
      const auto& accnt = control->db().get<account_object,by_name>( N(zsw.perms) );
      abi_def abi;
      BOOST_REQUIRE_EQUAL(abi_serializer::to_abi(accnt.abi, abi), true);
      abi_ser.set_abi(abi, abi_serializer::create_yield_function(abi_serializer_max_time));
   }

BOOST_AUTO_TEST_SUITE(zsw_perms_tests)

BOOST_FIXTURE_TEST_CASE( fake_test, zsw_perms_tester ) try {
   BOOST_REQUIRE_EQUAL( 1, 1 );
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
