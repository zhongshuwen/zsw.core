#include <eosio/eosio.hpp>
#include <zsw.perms/zsw.perms.hpp>

ACTION zswperms::setperms(eosio::name scope, eosio::name user, uint128_t perm_bits) {
    check(has_auth(scope) || has_auth("zsw.init"_n), "You can only call setperms on a scope that belongs to you.")
    auto tbl_permissions_scope = get_tbl_permissions(scope);
    auto itr = tbl_permissions_scope.find(user.value);

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


zswperms::t_permissions zswperms::get_tbl_permissions(name account) {
    return zswperms::t_permissions(get_self(), account.value);
}