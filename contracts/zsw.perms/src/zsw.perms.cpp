#include <eosio/eosio.hpp>
#include <zsw.perms/zsw.perms.hpp>
#include <zswinterfaces/zsw.perms-interface.hpp>
void zswperms::set_perms_internal(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits) {
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
}
ACTION zswperms::setperms(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits) {
    require_auth(sender);
    eosio::check(has_auth(scope) || has_auth("zsw.init"_n) || (
        ((perm_bits == 0||scope.value == ZSW_PERMS_CORE_SCOPE.value) && zswcore::get_zsw_perm_bits(
            ZSW_PERMS_CORE_SCOPE,
            sender

        )&ZSW_CORE_PERMS_ADMIN)!=0
    ), "You can only call setperms on a scope that belongs to you.");
    set_perms_internal(sender, scope, user, perm_bits);
}
ACTION zswperms::addperms(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits) {
    require_auth(sender);
    eosio::check(has_auth(scope) || has_auth("zsw.init"_n) || (
        (scope.value == ZSW_PERMS_CORE_SCOPE.value && zswcore::get_zsw_perm_bits(
            ZSW_PERMS_CORE_SCOPE,
            sender

        )&ZSW_CORE_PERMS_ADMIN)!=0
    ), "You can only call setperms on a scope that belongs to you.");

    set_perms_internal(sender, scope, user, zswcore::get_zsw_perm_bits(scope, user) | perm_bits);
}

ACTION zswperms::rmperms(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits) {
    require_auth(sender);
    eosio::check(has_auth(scope) || has_auth("zsw.init"_n) || (
        (zswcore::get_zsw_perm_bits(
            ZSW_PERMS_CORE_SCOPE,
            sender

        )&ZSW_CORE_PERMS_ADMIN)!=0
    ), "You can only call setperms on a scope that belongs to you.");

    set_perms_internal(sender, scope, user, (zswcore::get_zsw_perm_bits(scope, user) | perm_bits)^perm_bits);
}
zswperms::t_permissions zswperms::get_tbl_permissions(name acc) {
    return zswperms::t_permissions(get_self(), acc.value);
}
