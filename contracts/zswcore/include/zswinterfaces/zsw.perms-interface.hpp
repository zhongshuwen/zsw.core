/*

This file is not used for the actual zswperms contract.
It can be used as a header file for other contracts to access the zswperms tables
and custom data types.

*/

#include <eosio/eosio.hpp>

using namespace eosio;
typedef unsigned __int128 uint128_t;

/* START CORE PERM BITS */

#define ZSW_CORE_PERMS_SETCODE 1<<0
#define ZSW_CORE_PERMS_SETABI 1<<1

#define ZSW_CORE_PERMS_TRANSFER_TOKEN_TO_ANYONE 1<<2
#define ZSW_CORE_PERMS_RECEIVE_TOKEN_FROM_ANYONE 1<<3

#define ZSW_CORE_PERMS_TRANSFER_TOKEN_TO_CORE_CONTRACTS 1<<4
#define ZSW_CORE_PERMS_RECEIVE_TOKEN_AS_CORE_CONTRACTS 1<<5

/* END CORE PERM BITS */


#define ZSW_PERMS_CONTRACT_NAME "zsw.perms"_n
#define ZSW_PERMS_CORE_SCOPE "zsw.prmcore"_n

/* start macros */
/*
#define CAN_USERS_TRANSFER_TO_EACH_OTHER_PERM_BITS(from_perm_bits, to_perm_bits) \
    (\
        ((from_perm_bits & ZSW_CORE_PERMS_TRANSFER_TOKEN_TO_ANYONE)!=0) || \
        ((to_perm_bits & ZSW_CORE_PERMS_RECEIVE_TOKEN_FROM_ANYONE)!=0) || \
        (((to_perm_bits & ZSW_CORE_PERMS_RECEIVE_TOKEN_AS_CORE_CONTRACTS)!=0 && (from_perm_bits & ZSW_CORE_PERMS_TRANSFER_TOKEN_TO_CORE_CONTRACTS)!=0)) \
    )
*/

/* end macros */

namespace zswcore {

    TABLE s_permissions
    {
        eosio::name user;
        uint128_t perm_bits;
        uint64_t primary_key() const { return user.value; }
    };
    typedef multi_index <eosio::name("permissions"), s_permissions> t_permissions;
    
    static inline uint128_t get_zsw_perm_bits(const name &scope, const name &user)
    {
        auto tbl_perms = t_permissions(ZSW_PERMS_CONTRACT_NAME, scope.value);
        auto itr = tbl_perms.find(user.value);
        return itr == tbl_perms.end() ? 0 : itr->perm_bits;
    }
    static inline bool can_users_complete_transfer_perm_bits(uint128_t from_perm_bits, uint128_t to_perm_bits)
    {
        return (
            (from_perm_bits & ZSW_CORE_PERMS_TRANSFER_TOKEN_TO_ANYONE) != 0 ||
            (to_perm_bits & ZSW_CORE_PERMS_RECEIVE_TOKEN_FROM_ANYONE) != 0 ||
            (
                (to_perm_bits & ZSW_CORE_PERMS_RECEIVE_TOKEN_AS_CORE_CONTRACTS) != 0 &&
                (from_perm_bits & ZSW_CORE_PERMS_TRANSFER_TOKEN_TO_CORE_CONTRACTS)!=0
            )
        );
    }

}