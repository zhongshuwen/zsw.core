#pragma once

#include <eosio/eosio.hpp>
using namespace eosio;
/**
 * ZSW Perms
 */
class [[eosio::contract("zsw.perms")]] zswperms : public contract {
   public:
      using contract::contract;
      /**
       * Set Permissions.
       *
       * Set the permission bit array for a given scope and user
       * 
       * Preconditions:
       * - Requires user to have permissions for scope  (ie. require_auth(scope) must run without throwing an error)
       *
       * Postconditions:
       * - Permissions are set and ram is paid for by scope
       * 
       * @param scope - the scope of the permissions to be set
       * @param user - the user for which these permissions will apply
       * @param perm_bits - a 128 bit vector which determines the user's permissions for the given scope
       */
      ACTION setperms(eosio::name scope, eosio::name user, uint128_t perm_bits);


   private:
    //Scope: owner
    TABLE s_permissions {
        uint64_t         asset_id;
        name             collection_name;
        name             schema_name;
        int32_t          template_id;
        name             ram_payer;
        vector <asset>   backed_tokens;
        vector <uint8_t> immutable_serialized_data;
        vector <uint8_t> mutable_serialized_data;

        uint64_t primary_key() const { return asset_id; };
    };

    typedef multi_index <name("permissions"), s_permissions> t_permissions;
    t_permissions get_tbl_permissions(eosio::name acc);
};