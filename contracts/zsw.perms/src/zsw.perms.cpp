#include <eosio/eosio.hpp>
#include <zsw.perms/zsw.perms.hpp>
#include <zswinterfaces/zsw.perms-interface.hpp>

ACTION zswperms::setperms(eosio::name scope, eosio::name user, uint128_t perm_bits) {
    eosio::check(has_auth(scope) || has_auth("zsw.init"_n), "You can only call setperms on a scope that belongs to you.");
    eosio::print("test 1");
    auto tbl_permissions_scope = get_tbl_permissions(scope);
    eosio::print("test 2");
    auto itr = tbl_permissions_scope.find(user.value);
    eosio::print("test 3");

    eosio::name ram_payer = scope;
    eosio::print("test 4");

    if( itr == tbl_permissions_scope.end() ) {
    eosio::print("test 5");
    
        tbl_permissions_scope.emplace(_self, [&]( auto& row ) {
    eosio::print("test 5.1");
            row.user = user;
            row.perm_bits = perm_bits;
    eosio::print("test 5.2");
        });
    eosio::print("test 5.3");
    } else {
    eosio::print("test 6");
        tbl_permissions_scope.modify(itr, ram_payer, [&]( auto& row ) {
            row.user = user;
            row.perm_bits = perm_bits;
        });
    }
    eosio::print("test 7");
}

zswperms::t_permissions zswperms::get_tbl_permissions(name acc) {
    return zswperms::t_permissions(get_self(), acc.value);
}
