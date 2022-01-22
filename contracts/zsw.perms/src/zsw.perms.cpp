#include <eosio/eosio.hpp>
#include <zsw.perms/zsw.perms.hpp>
#include <zswinterfaces/zsw.perms-interface.hpp>

ACTION zswperms::setperms(eosio::name scope, eosio::name user, uint128_t perm_bits) {
    eosio::check(has_auth(scope) || has_auth("zsw.init"_n), "You can only call setperms on a scope that belongs to you.");
    auto tbl_permissions_scope = get_tbl_permissions(scope);
    auto itr = tbl_permissions_scope.find(user.value);
    eosio::name ram_payer = has_auth(scope)?scope:_self;
    if( itr == tbl_permissions_scope.end() ) {
        tbl_permissions_scope.emplace(ram_payer, [&]( auto& row ) {
            row.user = user;
            row.perm_bits = perm_bits;
        });
    } else {
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
