#pragma once

#include <eosio/eosio.hpp>
#include <zswcoredata/serializer.hpp>
using namespace zswcoredata;
using namespace eosio;
using namespace std;

#define ITEM_ISSUER_PERMS_MINT_ITEMS (1<<0)


#define ITEM_CONFIG_TRANSFERABLE (1<<0)
#define ITEM_CONFIG_BURNABLE (1<<1)
#define ITEM_CONFIG_FROZEN (1<<2)
#define ITEM_CONFIG_ALLOW_NOTIFY (1<<3)


#define ITEM_BALANCE_STATUS_SECOND_HAND (1<<0)
#define ITEM_BALANCE_STATUS_AUTHORIZER_LOCKED (1<<1)
#define ITEM_BALANCE_STATUS_FROZEN (1<<2)

#define ZSW_ITEMS_PERMS_SCOPE "zsw.items"_n
/**
 * ZSW Item
 */
class [[eosio::contract("zsw.items")]] zswitems : public contract {
   public:
      using contract::contract;
      ACTION mkissuer(
         name authorizer,
         name newissuer,
         uint128_t zsw_id,
         uint128_t alt_id,
         uint128_t permissions,
         uint32_t status
      );
      ACTION mkroyaltyusr(
         name authorizer,
         name newissuer,
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
         vector <name> authorized_accounts,
         ATTRIBUTE_MAP metadata
      );
      ACTION mkitem(
         name authorizer,
         name creator,
         name ram_payer,
         uint64_t item_id,
         uint64_t zsw_code,
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
      ACTION mint(
         name minter,
         name to,
         vector <uint64_t> item_ids,
         vector <uint64_t> amounts,
         string memo
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
         std::vector <uint64_t> item_ids,
         std::vector <uint64_t> amounts,
         std::string memo
      );


      ACTION logtransfer(
         name authorizer,
         name collection_name,
         name from,
         name to,
         std::vector <uint64_t> item_ids,
         std::vector <uint64_t> amounts,
         string memo
      );
      ACTION logmint(
         name minter,
         name collection_name,
         name to,
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
    typedef multi_index <name("issuerstatus"), s_royaltyusers,
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
        vector <name> authorized_accounts;
        vector <uint8_t> serialized_metadata;
        std::string external_metadata_url;
        uint64_t primary_key() const { return collection_id; };
    };

    typedef multi_index <name("collections"), s_collections> t_collections;


    TABLE s_items {
        uint64_t item_id;
        uint64_t zsw_code;
        uint32_t item_config;
        name creator;
        name ram_payer;
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

    TABLE s_itembalances {
        uint64_t item_id;
        uint32_t status;
        uint64_t balance;
        uint64_t primary_key() const { return item_id; };
    };
    typedef multi_index <name("itembalances"), s_itembalances> t_item_balances;

    t_schemas  tbl_schemas  = t_schemas(get_self(), get_self().value);
    t_issuerstatus  tbl_issuerstatus  = t_issuerstatus(get_self(), get_self().value);
    t_royaltyusers  tbl_royaltyusers  = t_royaltyusers(get_self(), get_self().value);
    t_collections  tbl_collections  = t_collections(get_self(), get_self().value);
    t_items  tbl_items  = t_items(get_self(), get_self().value);
    t_item_balances get_tbl_item_balances(eosio::name account);

    void zswitems::internal_transfer(
      name minter,
      name from,
      name to,
      vector <uint64_t> item_ids,
      vector <uint64_t> amounts,
      string memo,
      name scope_payer
   );
   void zswitems::internal_mint(
      name minter,
      name to,
      vector <uint64_t> item_ids,
      vector <uint64_t> amounts,
      string memo,
      name scope_payer
   );
   void zswitems::notify_collection_accounts(
      name collection_name
   );
};