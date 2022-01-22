#pragma once

#include <eosio/eosio.hpp>
#include <zswinterfaces/zsw.perms-interface.hpp>

/**
 * ZSW Perms
 */
class [[eosio::contract("zsw.perms")]] zswperms : public contract {
   public:
      using contract::contract;
      TABLE s_permissions
      {
         eosio::name user;
         uint128_t perm_bits;
         uint64_t primary_key() const { return user.value; }
      };
      typedef multi_index <eosio::name("permissions"), s_permissions> t_permissions;

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
      t_permissions get_tbl_permissions(eosio::name account);
};