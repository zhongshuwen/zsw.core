#pragma once

#include <eosio/eosio.hpp>
#include <eosio/system.hpp>

#include <zswcoredata/serializer.hpp>
using namespace zswcoredata;
using namespace eosio;
using namespace std;

#define NULL_CUSTODIAN_NAME ("nullnullnull"_n)
#define NULL_CUSTODIAN_ID 0
#define ZSW_CUSTODIAN_NAME ("zhongshuwen1"_n)
#define ZSW_CUSTODIAN_ID 1

#define CUSTODIAN_PERMS_ENABLED (1<<0)
#define CUSTODIAN_PERMS_TX_TO_SELF_CUSTODIAN (1<<1)
#define CUSTODIAN_PERMS_RECEIVE_FROM_NULL_CUSTODIAN (1<<2)
#define CUSTODIAN_PERMS_RECEIVE_FROM_ANY_CUSTODIAN (1<<3)
#define CUSTODIAN_PERMS_RECEIVE_FROM_ZSW_CUSTODIAN (1<<4)
#define CUSTODIAN_PERMS_SEND_TO_NULL_CUSTODIAN (1<<5)
#define CUSTODIAN_PERMS_SEND_TO_ANY_CUSTODIAN (1<<6)
#define CUSTODIAN_PERMS_SEND_TO_ZSW_CUSTODIAN (1<<7)

#define ITEM_CONFIG_TRANSFERABLE (1<<0)
#define ITEM_CONFIG_BURNABLE (1<<1)
#define ITEM_CONFIG_FROZEN (1<<2)
#define ITEM_CONFIG_ALLOW_NOTIFY (1<<3)


#define ITEM_BALANCE_STATUS_SECOND_HAND (1<<0)
#define ITEM_BALANCE_STATUS_AUTHORIZER_LOCKED (1<<1)
#define ITEM_BALANCE_STATUS_FROZEN (1<<2)

#define ZSW_ITEMS_PERMS_SCOPE "zsw.items"_n

#define CREATE_FROZEN_ID_BY_CUSTODIAN(custodian_id, item_id, unfreezes_at) \
    ((((uint128_t)custodian_id)<<96) | (((uint128_t)item_id)<<32) | ((uint128_t)unfreezes_at))

#define GET_CUSTODIAN_ID_FROM_CUSTODY_BALANCE_ID(custody_balance_id) \
    ((custody_balance_id>>40) & 0xffffff)

#define GET_ITEM_ID_FROM_CUSTODY_BALANCE_ID(custody_balance_id) \
    (custody_balance_id & 0xffffffffff)

#define CREATE_CUSTODY_BALANCE_ID_BY_CUSTODIAN(custodian_id, item_id) \
    ((((uint64_t)custodian_id)<<40) | (((uint64_t)item_id)&0xffffffffff))


#define CREATE_CUSTODY_BALANCE_ID_BY_ITEM_ID(custodian_id, item_id) \
    (((((uint64_t)item_id)&0xffffffffff)<<24) | (((uint64_t)custodian_id)&0xffffff))



/**
 * ZSW Item
 */
class [[eosio::contract("zsw.items")]] zswitems : public contract {
   public:
      using contract::contract;
      ACTION mkissuer(
         name authorizer,
         name issuer_name,
         uint128_t zsw_id,
         uint128_t alt_id,
         uint128_t permissions,
         uint32_t status
      );
      ACTION mkcustodian(
         name authorizer,
         name custodian_name,
         uint128_t zsw_id,
         uint128_t alt_id,
         uint128_t permissions,
         uint32_t status
      );
      ACTION mkroyaltyusr(
         name authorizer,
         name newroyaltyusr,
         uint128_t zsw_id,
         uint128_t alt_id,
         uint32_t status
      );

      ACTION mkcollection(
         name authorizer,
         name creator,
         name issuing_platform,
         uint64_t collection_id,
         uint64_t zsw_code,
         uint32_t collection_type, 
         uint32_t item_config,
         uint16_t secondary_market_fee, 
         uint16_t primary_market_fee, 
         name schema_name,
         std::string external_metadata_url,
         name royalty_fee_collector,
         vector <name> notify_accounts,
         ATTRIBUTE_MAP metadata
      );
      ACTION mkitem(
         name authorizer,
         name creator,
         name authorized_minter,
         uint64_t item_id,
         uint128_t zsw_id,
         uint32_t item_config,
         uint64_t collection_id,
         uint64_t max_supply,
         uint32_t item_type,
         std::string external_metadata_url,
         name schema_name,
         ATTRIBUTE_MAP metadata
      );

      ACTION mkschema(
         name authorizer,
         name creator,
         name schema_name,
         vector <FORMAT> schema_format
      );
      ACTION setuserperms(
         name sender,
         name user,
         uint128_t permissions
      );
      ACTION mint(
         name minter,
         name to,
         name to_custodian,
         vector <uint64_t> item_ids,
         vector <uint64_t> amounts,
         string memo,
         uint32_t freeze_time
      );
      ACTION init(name initializer);

      /**
       * 
       * @param authorizer - the authorizer of the user transaction
       * @param from - the sender of the items
       * @param to - the recipient of the items
       * @param item_ids - list of item ids
       * @param amounts - amounts of each item to send
       * @param memo - tx memo
       */
      ACTION transfer(
         name authorizer,
         name from,
         name to,
         name from_custodian,
         name to_custodian,
         uint32_t freeze_time,
         bool use_liquid_backup,
         uint32_t max_unfreeze_iterations,
         vector <uint64_t> item_ids,
         vector <uint64_t> amounts,
         string memo
      );


      ACTION logtransfer(
         name authorizer,
         uint64_t collection_id,
         name from,
         name to,
         name from_custodian,
         name to_custodian,
         std::vector <uint64_t> item_ids,
         std::vector <uint64_t> amounts,
         string memo
      );
      ACTION logmint(
         name minter,
         uint64_t collection_id,
         name to,
         name to_custodian,
         vector <uint64_t> item_ids,
         vector <uint64_t> amounts,
         string memo
      );

private:
   TABLE s_schemas {
        name            schema_name;
        vector <FORMAT> format;

        uint64_t primary_key() const { return schema_name.value; }
    };
    typedef multi_index <name("schemas"), s_schemas> t_schemas;
   
    TABLE s_issuerstatus {
        name issuer_name;
        uint128_t zsw_id;
        uint128_t alt_id;
        uint128_t permissions;
        uint32_t status;
        uint64_t primary_key() const { return issuer_name.value; }
        uint128_t by_zsw_id() const { return zsw_id; }
    };
    typedef multi_index <name("issuerstatus"), s_issuerstatus,
      indexed_by<name("byzswid"), eosio::const_mem_fun<s_issuerstatus, uint128_t, &s_issuerstatus::by_zsw_id> >
    > t_issuerstatus;

    TABLE s_custodians {
        uint64_t custodian_id;
        name custodian_name;
        uint128_t zsw_id;
        uint128_t alt_id;
        uint128_t permissions;
        uint32_t status;
        uint32_t incoming_freeze_period;
        vector <name> notify_accounts;
        uint64_t primary_key() const { return custodian_id; }
        uint64_t by_name() const { return custodian_name.value; }
        uint128_t by_zsw_id() const { return zsw_id; }
    };
    typedef multi_index <name("custodians"), s_custodians,
      indexed_by<name("byname"), eosio::const_mem_fun<s_custodians, uint64_t, &s_custodians::by_name> >,
      indexed_by<name("byzswid"), eosio::const_mem_fun<s_custodians, uint128_t, &s_custodians::by_zsw_id> >
    > t_custodians;

    TABLE s_royaltyusers {
        name user_name;
        uint128_t zsw_id;
        uint128_t alt_id;
        uint32_t status;
        uint64_t reported_fees_3rd;
        uint64_t reported_fees_zsw;
        uint64_t uncollected_fees_3rd;
        uint64_t uncollected_fees_zsw;

        uint64_t primary_key() const { return user_name.value; }
        uint128_t by_zsw_id() const { return zsw_id; }
    };
    typedef multi_index <name("royaltyusers"), s_royaltyusers,
      indexed_by<name("byzswid"), eosio::const_mem_fun<s_royaltyusers, uint128_t, &s_royaltyusers::by_zsw_id> >
    > t_royaltyusers;




    TABLE s_collections {
        uint64_t collection_id;
        uint64_t zsw_code;
        uint32_t collection_type; // 0 -> zsw collection, 1 -> standard grouping
        name creator;
        name issuing_platform;
        uint32_t item_config;
        uint16_t secondary_market_fee; // 0-10000, 0 is 0%, 10000 is 100% 5000 is 50%, 352 is 3.52%, etc
        uint16_t primary_market_fee; // 0-10000, 0 is 0%, 10000 is 100% 5000 is 50%, 352 is 3.52%, etc
        name schema_name;
        name royalty_fee_collector;
        vector <name> notify_accounts;
        vector <uint8_t> serialized_metadata;
        std::string external_metadata_url;
        uint64_t primary_key() const { return collection_id; };
    };

    typedef multi_index <name("collections"), s_collections> t_collections;


    TABLE s_items {
        uint64_t item_id;
        uint128_t zsw_id;
        uint32_t item_config;
        name creator;
        name authorized_minter;
        uint64_t collection_id;
        uint64_t total_supply;
        uint64_t max_supply;
        uint32_t item_type;
        name schema_name;
        vector <uint8_t> serialized_metadata;
        std::string external_metadata_url;
        uint64_t primary_key() const { return item_id; };
    };
    typedef multi_index <name("items"), s_items> t_items;

    TABLE s_custody_balances {
        uint64_t custody_balance_id;
        uint64_t balance;
        uint32_t status;
        uint64_t primary_key() const { return custody_balance_id; };
        uint64_t by_item_id() const { return ((custody_balance_id&0xffffffffff)<<24)|((custody_balance_id>>40)&0xffffff); };
    };
    
    typedef multi_index <name("custodybals"), s_custody_balances,
      indexed_by<name("byitemid"), eosio::const_mem_fun<s_custody_balances, uint64_t, &s_custody_balances::by_item_id> >
    > t_custody_balances;


    TABLE s_frozen_balances {
        uint64_t frozen_balance_id;
        uint64_t balance;
        uint32_t custodian_id;
        uint32_t unfreezes_at;
        uint64_t item_id;
        uint64_t primary_key() const { return frozen_balance_id; };
        uint128_t by_custodian_id() const { return CREATE_FROZEN_ID_BY_CUSTODIAN(custodian_id, item_id, unfreezes_at); };
    };
    
    typedef multi_index <name("frozenbals"), s_frozen_balances,
      indexed_by<name("bycustodian"), eosio::const_mem_fun<s_frozen_balances, uint128_t, &s_frozen_balances::by_custodian_id> >
    > t_frozen_balances;

    TABLE s_itembalances {
        uint64_t item_id;
        uint32_t status;
        uint64_t balance;
        uint64_t balance_in_custody;
        uint64_t balance_frozen;
        uint64_t primary_key() const { return item_id; };
    };
    typedef multi_index <name("itembalances"), s_itembalances> t_item_balances;

    t_schemas  tbl_schemas  = t_schemas(get_self(), get_self().value);
    t_issuerstatus  tbl_issuerstatus  = t_issuerstatus(get_self(), get_self().value);
    t_royaltyusers  tbl_royaltyusers  = t_royaltyusers(get_self(), get_self().value);
    t_collections  tbl_collections  = t_collections(get_self(), get_self().value);
    t_custodians  tbl_custodians  = t_custodians(get_self(), get_self().value);
    t_items  tbl_items  = t_items(get_self(), get_self().value);
    t_item_balances get_tbl_item_balances(eosio::name account);
    t_frozen_balances get_tbl_frozen_balances(eosio::name account);
    t_custody_balances get_tbl_custody_balances(eosio::name account);


    uint32_t require_get_custodian_id_with_permissions(eosio::name account, uint128_t permissions);




    void internal_transfer(
      name minter,
      name from,
      name to,
      vector <uint64_t> item_ids,
      vector <uint64_t> amounts,
      string memo,
      name scope_payer,
      name from_custodian,
      name to_custodian,
      uint32_t freeze_time,
      bool can_use_liquid_and_custodian,
      uint32_t max_unfreeze_iterations
   );
   void internal_mint(
      name minter,
      name to,
      name to_custodian,
      vector <uint64_t> item_ids,
      vector <uint64_t> amounts,
      string memo,
      name scope_payer,
      uint32_t freeze_time
   );
   void notify_collection_accounts(
      uint64_t collection_id
   );
   void notify_custodian_accounts(
      name custodian
   );

   void add_to_user_balance(
      name user,
      name custodian,
      uint32_t custodian_id,
      t_item_balances to_item_balances,
      t_custody_balances to_custody_balances,
      t_frozen_balances to_frozen_balances,
      name ram_payer,
      uint64_t item_id,
      uint64_t amount,
      uint32_t unfreezes_at
   );

   void sub_from_user_balance(
      name user,
      name custodian,
      uint32_t custodian_id,
      t_item_balances from_item_balances,
      t_custody_balances from_custody_balances,
      t_frozen_balances from_frozen_balances,
      name ram_payer,
      uint64_t item_id,
      uint64_t amount,
      bool can_use_liquid_and_custodian,
      uint32_t max_unfreeze_iterations
   );

   uint64_t unfreeze_up_to_amount(
      name user,
      uint32_t custodian_id,
      t_item_balances from_item_balances,
      t_custody_balances from_custody_balances,
      t_frozen_balances from_frozen_balances,
      name ram_payer,
      uint64_t item_id,
      uint64_t amount,
      uint32_t max_iterations
   );

};