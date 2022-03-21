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

#define CUSTODIAN_PERMS_ENABLED (1 << 0)
#define CUSTODIAN_PERMS_TX_TO_SELF_CUSTODIAN (1 << 1)
#define CUSTODIAN_PERMS_RECEIVE_FROM_NULL_CUSTODIAN (1 << 2)
#define CUSTODIAN_PERMS_RECEIVE_FROM_ANY_CUSTODIAN (1 << 3)
#define CUSTODIAN_PERMS_RECEIVE_FROM_ZSW_CUSTODIAN (1 << 4)
#define CUSTODIAN_PERMS_SEND_TO_NULL_CUSTODIAN (1 << 5)
#define CUSTODIAN_PERMS_SEND_TO_ANY_CUSTODIAN (1 << 6)
#define CUSTODIAN_PERMS_SEND_TO_ZSW_CUSTODIAN (1 << 7)

#define ITEM_CONFIG_TRANSFERABLE (1 << 0)
#define ITEM_CONFIG_BURNABLE (1 << 1)
#define ITEM_CONFIG_FROZEN (1 << 2)
#define ITEM_CONFIG_ALLOW_NOTIFY (1 << 3)
#define ITEM_CONFIG_ALLOW_MUTABLE_DATA (1 << 4)

#define ITEM_BALANCE_STATUS_SECOND_HAND (1 << 0)
#define ITEM_BALANCE_STATUS_AUTHORIZER_LOCKED (1 << 1)
#define ITEM_BALANCE_STATUS_FROZEN (1 << 2)

#define ZSW_ITEMS_PERMS_SCOPE "zsw.items"_n

#define MAX_PROFIT_SHARING_FEE_PRIMARY 5000
#define MAX_PROFIT_SHARING_FEE_SECONDARY 5000

#define CREATE_FROZEN_ID_BY_CUSTODIAN(custodian_id, item_id, unfreezes_at) \
   ((((uint128_t)custodian_id) << 96) | (((uint128_t)item_id) << 32) | ((uint128_t)unfreezes_at))

#define GET_CUSTODIAN_ID_FROM_CUSTODY_BALANCE_ID(custody_balance_id) \
   ((custody_balance_id >> 40) & 0xffffff)

#define GET_ITEM_ID_FROM_CUSTODY_BALANCE_ID(custody_balance_id) \
   (custody_balance_id & 0xffffffffff)

#define CREATE_CUSTODY_BALANCE_ID_BY_CUSTODIAN(custodian_id, item_id) \
   ((((uint64_t)custodian_id) << 40) | (((uint64_t)item_id) & 0xffffffffff))

#define CREATE_CUSTODY_BALANCE_ID_BY_CUSTODIAN(custodian_id, item_id) \
   ((((uint64_t)custodian_id) << 40) | (((uint64_t)item_id) & 0xffffffffff))

#define CREATE_CUSTODY_BALANCE_ID_BY_ITEM_ID(custodian_id, item_id) \
   (((((uint64_t)item_id) & 0xffffffffff) << 24) | (((uint64_t)custodian_id) & 0xffffff))

#define CREATE_FROZEN_BALANCE_ID(item_id, freeze_time) \
   (((((uint64_t)item_id) & 0xffffffffff) << 24) | (((uint64_t)freeze_time) & 0xffffff))

uint64_t static inline add_no_overflow(uint64_t a, uint64_t b)
{
   check((0xffffffffffffffff - a) >= b, "add overflow");
   return a + b;
}

uint32_t static inline get_current_time_minutes()
{
   return (eosio::current_time_point().sec_since_epoch() / 60) - 27349440;
}
std::vector<uint64_t> ensure_in_list(std::vector<uint64_t> &list, uint64_t value)
{
   if (std::find(list.begin(), list.end(), value) == list.end())
   {
      list.push_back(value);
   }
   return list;
}
/**
 * ZSW Item
 */
class [[eosio::contract("zsw.items")]] zswitems : public contract
{
public:
   using contract::contract;
   ACTION mkissuer(
       name authorizer,
       name issuer_name,
       uint128_t zsw_id,
       uint128_t alt_id,
       uint128_t permissions,
       uint32_t status);
   ACTION mkcustodian(
       name creator,
       name custodian_name,
       uint128_t zsw_id,
       uint128_t alt_id,
       uint128_t permissions,
       uint32_t status,
       uint32_t incoming_freeze_period,
       vector<name> notify_accounts);
   ACTION mkroyaltyusr(
       name authorizer,
       name newroyaltyusr,
       uint128_t zsw_id,
       uint128_t alt_id,
       uint32_t status);

   ACTION mkcollection(
       name authorizer,
       uint128_t zsw_id,
       uint64_t collection_id,
       uint32_t collection_type,
       name creator,
       name issuing_platform,
       uint32_t item_config,
       uint16_t secondary_market_fee,
       uint16_t primary_market_fee,
       name royalty_fee_collector,
       uint64_t max_supply,
       uint64_t max_items,
       uint64_t max_supply_per_item,
       name schema_name,
       vector<name> authorized_minters,
       vector<name> notify_accounts,
       vector<name> authorized_mutable_data_editors,
       ATTRIBUTE_MAP metadata,
       std::string external_metadata_url);
   ACTION mkitem(
       name authorizer,
       name authorized_minter,
       uint64_t item_id,
       uint128_t zsw_id,
       uint32_t item_config,
       uint64_t item_template_id,
       uint64_t max_supply,
       name schema_name,
       ATTRIBUTE_MAP immutable_metadata,
       ATTRIBUTE_MAP mutable_metadata);

   ACTION logmkitem(
       name authorizer,
       name authorized_minter,
       uint64_t item_id,
       uint128_t zsw_id,
       uint32_t item_config,
       uint64_t item_template_id,
       uint64_t max_supply,
       name schema_name,
       uint64_t collection_id,
       ATTRIBUTE_MAP immutable_metadata,
       ATTRIBUTE_MAP mutable_metadata,
       ATTRIBUTE_MAP immutable_template_data);

   ACTION mkschema(
       name authorizer,
       name creator,
       name schema_name,
       vector<FORMAT> schema_format);

   ACTION mkitemtpl(
       name authorizer,
       name creator,
       uint128_t zsw_id,
       uint64_t item_template_id,
       uint64_t collection_id,
       uint32_t item_type,
       name schema_name,
       ATTRIBUTE_MAP immutable_metadata,
       std::string item_external_metadata_url_template);

   ACTION setitemdata(
       name authorized_editor,
       uint64_t item_id,
       ATTRIBUTE_MAP new_mutable_data);

   ACTION logsetdata(
       name authorized_editor,
       uint64_t item_id,
       uint64_t collection_id,
       ATTRIBUTE_MAP old_data,
       ATTRIBUTE_MAP new_data);

   ACTION setuserperms(
       name sender,
       name user,
       uint128_t permissions);
   ACTION setcustperms(
       name sender,
       name custodian,
       uint128_t permissions);
   ACTION mint(
       name minter,
       name to,
       name to_custodian,
       vector<uint64_t> item_ids,
       vector<uint64_t> amounts,
       string memo,
       uint32_t freeze_time);
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
       vector<uint64_t> item_ids,
       vector<uint64_t> amounts,
       string memo);

   ACTION logtransfer(
       name authorizer,
       uint64_t collection_id,
       name from,
       name to,
       name from_custodian,
       name to_custodian,
       std::vector<uint64_t> item_ids,
       std::vector<uint64_t> amounts,
       string memo);
   ACTION logmint(
       name minter,
       uint64_t collection_id,
       name to,
       name to_custodian,
       vector<uint64_t> item_ids,
       vector<uint64_t> amounts,
       string memo);

   ACTION logmkitemtpl(
       name authorizer,
       name creator,
       uint128_t zsw_id,
       uint64_t item_template_id,
       uint64_t collection_id,
       uint32_t item_type,
       name schema_name,
       ATTRIBUTE_MAP immutable_metadata,
       std::string item_external_metadata_url_template);

private:
   TABLE s_schemas
   {
      name schema_name;
      vector<FORMAT> format;

      uint64_t primary_key() const { return schema_name.value; }
   };
   typedef multi_index<name("schemas"), s_schemas> t_schemas;

   TABLE s_issuerstatus
   {
      name issuer_name;
      uint128_t zsw_id;
      uint128_t alt_id;
      uint128_t permissions;
      uint32_t status;
      uint64_t primary_key() const { return issuer_name.value; }
      uint128_t by_zsw_id() const { return zsw_id; }
   };
   typedef multi_index<name("issuerstatus"), s_issuerstatus,
                       indexed_by<name("byzswid"), eosio::const_mem_fun<s_issuerstatus, uint128_t, &s_issuerstatus::by_zsw_id>>>
       t_issuerstatus;

   TABLE s_custodians
   {
      uint64_t custodian_id;
      name custodian_name;
      uint128_t zsw_id;
      uint128_t alt_id;
      uint128_t permissions;
      uint32_t status;
      uint32_t incoming_freeze_period;
      vector<name> notify_accounts;
      uint64_t primary_key() const { return custodian_id; }
      uint64_t by_name() const { return custodian_name.value; }
      uint128_t by_zsw_id() const { return zsw_id; }
   };
   typedef multi_index<name("custodians"), s_custodians,
                       indexed_by<name("byname"), eosio::const_mem_fun<s_custodians, uint64_t, &s_custodians::by_name>>,
                       indexed_by<name("byzswid"), eosio::const_mem_fun<s_custodians, uint128_t, &s_custodians::by_zsw_id>>>
       t_custodians;

   TABLE s_royaltyusers
   {
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
   typedef multi_index<name("royaltyusers"), s_royaltyusers,
                       indexed_by<name("byzswid"), eosio::const_mem_fun<s_royaltyusers, uint128_t, &s_royaltyusers::by_zsw_id>>>
       t_royaltyusers;

   TABLE s_collections
   {
      uint128_t zsw_id;
      uint32_t collection_type; // 0 -> zsw collection, 1 -> standard grouping
      name creator;
      name issuing_platform;
      uint32_t item_config;
      uint16_t secondary_market_fee; // 0-10000, 0 is 0%, 10000 is 100% 5000 is 50%, 352 is 3.52%, etc
      uint16_t primary_market_fee;   // 0-10000, 0 is 0%, 10000 is 100% 5000 is 50%, 352 is 3.52%, etc

      name royalty_fee_collector;

      uint64_t issued_supply;
      uint64_t max_supply;

      uint64_t items_count;
      uint64_t max_items;
      uint64_t max_supply_per_item;

      name schema_name;
      vector<name> authorized_minters;
      vector<name> notify_accounts;
      vector<name> authorized_mutable_data_editors;
      vector<uint8_t> serialized_metadata;
      std::string external_metadata_url;
      uint64_t primary_key() const { return zsw_id & 0xffffffffffffffff; };
   };

   typedef multi_index<name("collections"), s_collections> t_collections;

   TABLE s_item_templates
   {
      uint128_t zsw_id;       // 16 = 16
      uint64_t collection_id; // 8 = 28
      uint32_t item_type;     // 4 = 32

      name schema_name; // 8 = 64

      vector<uint8_t> serialized_immutable_metadata; // 8? = 72

      std::string item_external_metadata_url_template;                      // 8? = 80
      uint64_t primary_key() const { return zsw_id & 0xffffffffffffffff; }; // 8? = 96
   };
   typedef multi_index<name("itemtemplate"), s_item_templates> t_item_templates;

   TABLE s_items
   {
      uint128_t zsw_id;                                               // 16 = 16
      uint32_t item_config;                                           // 4 = 20
      uint64_t item_template_id;                                      // 8 = 24
      uint64_t collection_id;                                         // 8 = 24
      uint64_t issued_supply;                                         // 8 = 32
      uint64_t max_supply;                                            // 8 = 40
      name schema_name;                                               // 8 = 48
      vector<uint8_t> serialized_immutable_metadata;                  // 8? = 56
      vector<uint8_t> serialized_mutable_metadata;                    // 8? = 64
      uint64_t primary_key() const { return zsw_id & 0xffffffffff; }; // 8? = 72
   };
   typedef multi_index<name("items"), s_items> t_items;

   TABLE s_frozen_balances
   {
      uint64_t frozen_balance_id;                                 // 8 = 8
      uint64_t balance;                                           // 8 = 16
      uint32_t status;                                            // 4 = 20
      uint64_t primary_key() const { return frozen_balance_id; }; // 8? = 24
   };

   typedef multi_index<name("frozenbals"), s_frozen_balances> t_frozen_balances;

   TABLE s_custodian_user_pairs
   {
      uint64_t custodian_user_pair_id;                                                                      // 8 = 8
      name user;                                                                                            // 8 = 16
      name custodian;                                                                                       // 8 = 24
      uint64_t primary_key() const { return custodian_user_pair_id; };                                      // 8 = 32
      uint128_t by_user() const { return (((uint128_t)user.value) << 64) | ((uint128_t)custodian.value); }; // 8 = 40 * 2 = 80
   };

   typedef multi_index<name("custodianups"), s_custodian_user_pairs,
                       indexed_by<name("byuser"), eosio::const_mem_fun<s_custodian_user_pairs, uint128_t, &s_custodian_user_pairs::by_user>>>
       t_custodian_user_pairs;

   TABLE s_itembalances
   {
      uint64_t item_id;                                 // 8 = 8
      uint32_t status;                                  // 4 = 12
      uint64_t balance_normal_liquid;                   // 8 = 20
      uint64_t balance_frozen;                          // 8 = 28
      uint64_t balance_in_custody_liquid;               // 8 = 36
      vector<uint64_t> active_custodian_pairs;          // 8? = 44
      uint64_t primary_key() const { return item_id; }; // 8? = 52
   };
   typedef multi_index<name("itembalances"), s_itembalances> t_item_balances;

   t_schemas tbl_schemas = t_schemas(get_self(), get_self().value);
   t_issuerstatus tbl_issuerstatus = t_issuerstatus(get_self(), get_self().value);
   t_royaltyusers tbl_royaltyusers = t_royaltyusers(get_self(), get_self().value);
   t_collections tbl_collections = t_collections(get_self(), get_self().value);
   t_custodians tbl_custodians = t_custodians(get_self(), get_self().value);
   t_item_templates tbl_item_templates = t_item_templates(get_self(), get_self().value);

   t_custodian_user_pairs tbl_custodian_user_pairs = t_custodian_user_pairs(get_self(), get_self().value);
   t_items tbl_items = t_items(get_self(), get_self().value);
   t_item_balances get_tbl_item_balances(eosio::name account);
   t_frozen_balances get_tbl_frozen_balances(uint64_t custodian_user_pair_id);

   uint32_t require_get_custodian_id_with_permissions(eosio::name account, uint128_t permissions);

   void internal_transfer(
       name authorizer,
       name from,
       name to,
       vector<uint64_t> item_ids,
       vector<uint64_t> amounts,
       string memo,
       name scope_payer,
       name from_custodian,
       name to_custodian,
       uint32_t freeze_time,
       bool can_use_liquid_and_custodian,
       uint32_t max_unfreeze_iterations);
   void internal_mint(
       name minter,
       name to,
       name to_custodian,
       vector<uint64_t> item_ids,
       vector<uint64_t> amounts,
       string memo,
       name scope_payer,
       uint32_t freeze_time);
   void notify_collection_accounts(
       uint64_t collection_id);
   void notify_custodian_accounts(
       name custodian);

   void add_to_user_balance(
       name user,
       name custodian,
       uint64_t custodian_user_pair_id,
       name ram_payer,
       uint64_t item_id,
       uint64_t amount,
       uint32_t unfreezes_at);

   void sub_from_user_balance(
       name user,
       name custodian,
       uint64_t custodian_user_pair_id,
       name ram_payer,
       uint64_t item_id,
       uint64_t amount,
       bool can_use_liquid_and_custodian,
       uint32_t max_unfreeze_iterations);
   /*
      uint64_t unfreeze_up_to_amount(
         name user,
         uint32_t custodian_id,
         name ram_payer,
         uint64_t item_id,
         uint64_t amount,
         uint32_t max_iterations
      );

   */
   uint64_t unfreeze_amount(
       uint64_t custodian_user_pair_id,
       name ram_payer,
       uint64_t item_id,
       uint64_t target_amount,
       uint32_t max_unfreeze_iterations);
   uint64_t get_custodian_user_pair_id(name ram_payer, name custodian, name user);
};