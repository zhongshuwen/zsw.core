#include <eosio/eosio.hpp>
#include <zsw.perms/zsw.perms.hpp>

ACTION zswperms::setperms(eosio::name scope, eosio::name user, uint128_t perm_bits) {
    require_auth(scope);
    auto tbl_permissions_scope = get_tbl_permissions(scope);
    auto itr = tbl_permissions_scope.find(user.value);
    eosio::check( itr != tbl_permissions_scope.end(), "table val not set" );

    eosio::name ram_payer = scope;

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
}


t_permissions zswperms::get_tbl_permissions(name account) {
    return t_permissions(get_self(), account.value);
}