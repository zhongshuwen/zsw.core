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
       * @param sender - the user execution this action
       * @param scope - the scope of the permissions to be set
       * @param user - the user for which these permissions will apply
       * @param perm_bits - a 128 bit vector which determines the user's permissions for the given scope
       */
      [[eosio::action]]
      void setperms(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits);
      using setperms_action = action_wrapper<"setperms"_n, &zswperms::setperms>;

      /**
       * Add Permissions.
       *
       * Add the permissions specififed in the bit array `perm_bits` for a given scope to a user
       * 
       * Preconditions:
       * - Requires user to have permissions for scope  (ie. require_auth(scope) must run without throwing an error)
       *
       * Postconditions:
       * - Permissions are set and ram is paid for by scope
       * 
       * @param sender - the user execution this action
       * @param scope - the scope of the permissions to be set
       * @param user - the user for which these permissions will apply
       * @param perm_bits - a 128 bit vector which determines the new user's permissions to add for the given scope
       */
      [[eosio::action]]
      void addperms(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits);
      using addperms_action = action_wrapper<"addperms"_n, &zswperms::addperms>;

      /**
       * Remove Permissions.
       *
       * Remove the permissions specififed in the bit array `perm_bits` for a given scope to a user
       * 
       * Preconditions:
       * - Requires user to have permissions for scope  (ie. require_auth(scope) must run without throwing an error)
       *
       * Postconditions:
       * - Permissions are set and ram is paid for by scope
       * 
       * @param sender - the user execution this action
       * @param scope - the scope of the permissions to be set
       * @param user - the user for which these permissions will apply
       * @param perm_bits - a 128 bit vector which determines the user's permissions to remove for the given scope
       */
      [[eosio::action]]
      void rmperms(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits);
      using rmperms_action = action_wrapper<"rmperms"_n, &zswperms::rmperms>;


   private:
    //Scope: owner
    TABLE s_permissions {
      eosio::name user;
      uint128_t perm_bits;
      uint64_t primary_key() const { return user.value; }
    };
      void set_perms_internal(eosio::name sender, eosio::name scope, eosio::name user, uint128_t perm_bits);

    typedef multi_index <name("permissions"), s_permissions> t_permissions;
    t_permissions get_tbl_permissions(eosio::name acc);
};