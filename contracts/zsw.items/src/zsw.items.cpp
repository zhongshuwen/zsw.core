#include <eosio/eosio.hpp>
#include <zsw.items/zsw.items.hpp>
#include <zswinterfaces/zsw.perms-interface.hpp>
#include <zswinterfaces/zsw.items-interface.hpp>
#include <zsw.perms/zsw.perms.hpp>
#include <zswcoredata/checkformat.hpp>
using namespace eosio;

ACTION zswitems::init(name initializer) {
    require_auth(initializer);
    auto itr = tbl_schemas.find(""_n.value);
    check(itr == tbl_schemas.end(), "zswitems already initialized (1)!");
    tbl_schemas.emplace(initializer, [&]( auto& _schema ) {
        _schema.schema_name = ""_n;
        _schema.format = {};
    });
    auto itr_custodians = tbl_custodians.find(NULL_CUSTODIAN_ID);
    check(itr_custodians == tbl_custodians.end(), "zswitems already initialized (2)!");
    check(NULL_CUSTODIAN_ID == tbl_custodians.available_primary_key(),"null custodian id misconfigured!");
    tbl_custodians.emplace(initializer, [&]( auto& _custodian ) {
        _custodian.custodian_id = NULL_CUSTODIAN_ID;
        _custodian.custodian_name = NULL_CUSTODIAN_NAME;
        _custodian.zsw_id = NULL_CUSTODIAN_ID;
        _custodian.alt_id = 0;
        _custodian.permissions = CUSTODIAN_PERMS_ENABLED | 
            CUSTODIAN_PERMS_TX_TO_SELF_CUSTODIAN |
            CUSTODIAN_PERMS_RECEIVE_FROM_NULL_CUSTODIAN |
            CUSTODIAN_PERMS_RECEIVE_FROM_ANY_CUSTODIAN |
            CUSTODIAN_PERMS_RECEIVE_FROM_ZSW_CUSTODIAN |
            CUSTODIAN_PERMS_SEND_TO_NULL_CUSTODIAN |
            CUSTODIAN_PERMS_SEND_TO_ANY_CUSTODIAN |
            CUSTODIAN_PERMS_SEND_TO_ZSW_CUSTODIAN;
        _custodian.status = 0;
        _custodian.incoming_freeze_period = 0;
        _custodian.notify_accounts = {NULL_CUSTODIAN_NAME};
    });

    itr_custodians = tbl_custodians.find(ZSW_CUSTODIAN_ID);
    check(itr_custodians == tbl_custodians.end(), "zswitems already initialized (3)!");
    check(ZSW_CUSTODIAN_ID == tbl_custodians.available_primary_key(),"zsw custodian id misconfigured!");
    tbl_custodians.emplace(initializer, [&]( auto& _custodian ) {
        _custodian.custodian_id = ZSW_CUSTODIAN_ID;
        _custodian.custodian_name = ZSW_CUSTODIAN_NAME;
        _custodian.zsw_id = ZSW_CUSTODIAN_ID;
        _custodian.alt_id = ZSW_CUSTODIAN_ID;
        _custodian.permissions = CUSTODIAN_PERMS_ENABLED | 
            CUSTODIAN_PERMS_TX_TO_SELF_CUSTODIAN |
            CUSTODIAN_PERMS_RECEIVE_FROM_NULL_CUSTODIAN |
            CUSTODIAN_PERMS_RECEIVE_FROM_ANY_CUSTODIAN |
            CUSTODIAN_PERMS_RECEIVE_FROM_ZSW_CUSTODIAN |
            CUSTODIAN_PERMS_SEND_TO_NULL_CUSTODIAN |
            CUSTODIAN_PERMS_SEND_TO_ANY_CUSTODIAN |
            CUSTODIAN_PERMS_SEND_TO_ZSW_CUSTODIAN;
        _custodian.status = 0;
        _custodian.incoming_freeze_period = 0;
        _custodian.notify_accounts = {ZSW_CUSTODIAN_NAME};
    });
}
/**
*  Transfers one or more assets to another account
*  @required_auth The from account
*/
ACTION zswitems::transfer(
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
) {
    zswcore::require_transfer_authorizer(authorizer, from);
    if(from_custodian.value != NULL_CUSTODIAN_NAME.value){
        require_auth(from_custodian);
        if(use_liquid_backup){
            require_auth(from);
        }
    }else{
        require_auth(from);
    }
    require_recipient(from);
    require_recipient(to);
    internal_transfer(
        authorizer,
        from,
        to,
        item_ids,
        amounts,
        memo,
        authorizer,
        from_custodian,
        to_custodian,
        freeze_time,
        use_liquid_backup,
        max_unfreeze_iterations
    );
}
ACTION zswitems::mint(
    name minter,
    name to,
    name to_custodian,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo,
    uint32_t freeze_time
) {

    require_auth(minter);
    internal_mint(
        minter,
        to,
        to_custodian,
        item_ids,
        amounts,
        memo,
        minter,
        freeze_time
    );
}

ACTION zswitems::setuserperms(
         name sender,
         name user,
         uint128_t permissions
) {
    require_auth(sender);
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, sender) & ZSW_ITEMS_PERMS_ADMIN)!=0,
        "authorizer is not allowed to set user permissions"
    );
    zswperms::addperms_action addperms("zsw.perms"_n, {get_self(), "active"_n});
        addperms.send("zsw.items"_n,"zsw.items"_n,
        user,
        permissions
    );

}
ACTION zswitems::setcustperms(
         name sender,
         name custodian,
         uint128_t permissions
) {
    require_auth(sender);
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, sender) & ZSW_ITEMS_PERMS_ADMIN)!=0,
        "authorizer is not allowed to set user permissions"
    );
    auto custodian_byname_idx = tbl_custodians.get_index<name("byname")>();
    auto custodian_byname_itr = custodian_byname_idx.find(custodian.value);
    check(custodian_byname_itr != custodian_byname_idx.end(), "a custodian with this name does not exist!");

    custodian_byname_idx.modify(custodian_byname_itr, sender, [&](auto &_custodian) {
        _custodian.permissions = permissions;
    });
}
ACTION zswitems::mkschema(
    name authorizer,
    name creator,
    name schema_name,
    vector <FORMAT> schema_format
) {

    require_auth(creator);

    require_auth(authorizer);
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_SCHEMA)!=0,
        "authorizer is not allowed to create new schemas"
    );

    check(1 <= schema_name.length() && schema_name.length() <= 12,
        "Schema names must be between 1 and 12 characters long");



    auto itr = tbl_schemas.find(schema_name.value);
    check(itr == tbl_schemas.end(), "this schema already exists!");

    zswcoredata::check_serdata_format(schema_format);
    tbl_schemas.emplace(creator, [&]( auto& _schema ) {
        _schema.schema_name = schema_name;
        _schema.format = schema_format;
    });

}

ACTION zswitems::mkissuer(
    name authorizer,
    name issuer_name,
    uint128_t zsw_id,
    uint128_t alt_id,
    uint128_t permissions,
    uint32_t status
) {
    //require_auth(issuer_name);

    require_auth(authorizer);
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ISSUER)!=0,
        "authorizer is not allowed to create new issuers"
    );


    auto itr = tbl_issuerstatus.find(issuer_name.value);
    check(itr == tbl_issuerstatus.end(), "this issuer user already exists!");

    tbl_issuerstatus.emplace(authorizer, [&]( auto& _issuer_status ) {
        _issuer_status.issuer_name = issuer_name;
        _issuer_status.zsw_id = zsw_id;
        _issuer_status.alt_id = alt_id;
        _issuer_status.permissions = permissions;
        _issuer_status.status = status;
    });
    zswperms::addperms_action addperms("zsw.perms"_n, {get_self(), "active"_n});
        addperms.send("zsw.items"_n,"zsw.items"_n,issuer_name,
        ZSW_ITEMS_PERMS_AUTHORIZE_MINT_ITEM
    );


}
ACTION zswitems::mkroyaltyusr(
    name authorizer,
    name newroyaltyusr,
    uint128_t zsw_id,
    uint128_t alt_id,
    uint32_t status
) {
    //require_auth(newroyaltyusr);
    require_auth(authorizer);
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ROYALTY_USER)!=0,
        "authorizer is not allowed to create royalty users"
    );


    auto itr = tbl_royaltyusers.find(newroyaltyusr.value);
    check(itr == tbl_royaltyusers.end(), "this royalty user already exists!");

    tbl_royaltyusers.emplace(authorizer, [&]( auto& _royalty_user ) {
        _royalty_user.user_name = newroyaltyusr;
        _royalty_user.zsw_id = zsw_id;
        _royalty_user.alt_id = alt_id;
        _royalty_user.status = status;
        _royalty_user.reported_fees_3rd = 0;
        _royalty_user.reported_fees_zsw = 0;
        _royalty_user.uncollected_fees_3rd = 0;
        _royalty_user.uncollected_fees_zsw = 0;
    });


}

ACTION zswitems::mkcollection(
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
) {
    require_auth(creator);
    require_auth(issuing_platform);

    require_auth(authorizer);
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_COLLECTION)!=0,
        "authorizer is not allowed to create collections"
    );
    auto royaltyItr = tbl_royaltyusers.require_find(royalty_fee_collector.value,"royalty fee collector not yet approved");
    
    auto itr = tbl_collections.find(collection_id);
    check(itr == tbl_collections.end(), "this collection id already exists!");

    check(schema_name.value==name("").value, "schemas/metadata not yet supported!");


    tbl_collections.emplace(issuing_platform, [&]( auto& _collection ) {
        _collection.collection_id = collection_id;
        _collection.zsw_code = zsw_code;
        _collection.collection_type = collection_type; 
        _collection.creator = creator;
        _collection.issuing_platform = issuing_platform;
        _collection.item_config = item_config;
        _collection.secondary_market_fee = secondary_market_fee; 
        _collection.primary_market_fee = primary_market_fee; 
        _collection.schema_name = schema_name;
        _collection.royalty_fee_collector = royalty_fee_collector;
        _collection.notify_accounts = notify_accounts;
        _collection.serialized_metadata = {};
        _collection.external_metadata_url = external_metadata_url;
    });
}


ACTION zswitems::mkitem(
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
) {

    require_auth(creator);
    require_auth(authorizer);
    check((item_id & 0xffffffffff)==item_id,"item_id cannot be larger than 2^40-1");
    check(((uint64_t)(zsw_id&0xffffffffff)) == item_id, "item id must be the first 40 bits of the zsw_id!");

    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ITEM)!=0,
        "authorizer is not allowed to create new items"
    );
    check(schema_name.value==name("").value, "schemas/metadata not yet supported!");


    auto collection_itr = tbl_collections.require_find(collection_id, "collection does not exist!");
    require_auth(collection_itr->creator);

    auto itr = tbl_items.find(item_id);
    check(itr == tbl_items.end(), "this item already exists!");

    tbl_items.emplace(creator, [&]( auto& _item ) {
        _item.item_id = item_id;
        _item.zsw_id = zsw_id;
        _item.item_config = item_config;
        _item.creator = creator;
        _item.authorized_minter = authorized_minter;
        _item.collection_id = collection_id;
        _item.max_supply = max_supply;
        _item.item_type = item_type;
        _item.schema_name = schema_name;
        _item.serialized_metadata = {};
        _item.external_metadata_url = external_metadata_url;
    });

}

ACTION zswitems::mkcustodian(
    name creator,
    name custodian_name,
    uint128_t zsw_id,
    uint128_t alt_id,
    uint128_t permissions,
    uint32_t status,
    uint32_t incoming_freeze_period,
    vector <name> notify_accounts
) {

    require_auth(creator);
     
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, creator) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_CUSTODIAN)!=0,
        "creator is not allowed to create new custodians"
    );
    auto custodian_byname_idx = tbl_custodians.get_index<name("byname")>();
    auto custodian_byname_itr = custodian_byname_idx.find(custodian_name.value);
    check(custodian_byname_itr == custodian_byname_idx.end(), "a custodian with this name already exists!");
    
    auto custodian_zswid_idx = tbl_custodians.get_index<name("byzswid")>();
    auto custodian_zswid_itr = custodian_zswid_idx.find(zsw_id);
    check(custodian_zswid_itr == custodian_zswid_idx.end(), "a custodian with this zsw_id already exists!");


    tbl_custodians.emplace(creator, [&]( auto& _custodian ) {
        _custodian.custodian_id = tbl_custodians.available_primary_key();
        _custodian.custodian_name = custodian_name;
        _custodian.zsw_id = zsw_id;
        _custodian.alt_id = alt_id;
        _custodian.permissions = permissions;
        _custodian.status = status;
        _custodian.incoming_freeze_period = incoming_freeze_period;
        _custodian.notify_accounts = notify_accounts;
    });

}


ACTION zswitems::logtransfer(
    name authorizer,
    uint64_t collection_id,
    name from,
    name to,
    name from_custodian,
    name to_custodian,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo
) {
    require_auth(get_self());

    notify_collection_accounts(collection_id);
    notify_custodian_accounts(to_custodian);
}
ACTION zswitems::logmint(
    name minter,
    uint64_t collection_id,
    name to,
    name to_custodian,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo
) {
    require_auth(get_self());

    require_recipient(to);

    notify_collection_accounts(collection_id);
    notify_custodian_accounts(to_custodian);
}

static inline uint128_t get_custodian_to_flags_needed_for_transfer(name from, name to) {
    if(from.value == to.value){
        return CUSTODIAN_PERMS_TX_TO_SELF_CUSTODIAN;
    }else if(from.value == NULL_CUSTODIAN_NAME.value){
        return CUSTODIAN_PERMS_RECEIVE_FROM_NULL_CUSTODIAN;
    }else if(from.value == ZSW_CUSTODIAN_NAME.value){
        return CUSTODIAN_PERMS_RECEIVE_FROM_ZSW_CUSTODIAN;
    }else{
        return CUSTODIAN_PERMS_RECEIVE_FROM_ANY_CUSTODIAN;
    }
}
static inline uint128_t get_custodian_from_flags_needed_for_transfer(name from, name to) {
    if(from.value == to.value){
        return CUSTODIAN_PERMS_TX_TO_SELF_CUSTODIAN;
    }else if(to.value == NULL_CUSTODIAN_NAME.value){
        return CUSTODIAN_PERMS_SEND_TO_NULL_CUSTODIAN;
    }else if(to.value == ZSW_CUSTODIAN_NAME.value){
        return CUSTODIAN_PERMS_SEND_TO_ZSW_CUSTODIAN;
    }else{
        return CUSTODIAN_PERMS_SEND_TO_ANY_CUSTODIAN;
    }
}
/**
*  Transfers need to be handled like this (as a function instead of an action), because when accepting an offer,
*  we want each side of the offer to pay for their own scope. Because the recipient authorized the accept action,
*  he can be charged the RAM for his own scope, and because the offer is removed from the table, which was previously
*  paid by the offer sender, the action RAM delta for the sender account will still be positive even after paying
*  for the scope. This is allowed by the protocol feature RAM_RESTRICTIONS which needs to be enabled on the blockchain
*  that this contract is deployed on.
*/
void zswitems::internal_transfer(
    name authorizer,
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
) {
    check(is_account(to), "to account does not exist");

    check(from != to, "Can't transfer item_balances to yourself");

    check(item_ids.size() != 0, "item_ids needs to contain at least one id");
    check(item_ids.size() == amounts.size(), "item_ids should be the same size as amounts");

    check(memo.length() <= 256, "A transfer memo can only be 256 characters max");

    vector <uint64_t> item_ids_copy = item_ids;
    std::sort(item_ids_copy.begin(), item_ids_copy.end());
    check(std::adjacent_find(item_ids_copy.begin(), item_ids_copy.end()) == item_ids_copy.end(),
        "Can't transfer the same item_balance multiple times");
    
    uint32_t cur_time_sec = eosio::current_time_point().sec_since_epoch();
    check(0xffffffff-freeze_time>cur_time_sec, "freeze time set to high, leads to overflow (set in the next 100 years)!");
    uint32_t unfreezes_at = freeze_time == 0?0:(freeze_time+cur_time_sec);

    
    // start check permissions
    uint32_t from_custodian_id = require_get_custodian_id_with_permissions(
        from_custodian,
        get_custodian_from_flags_needed_for_transfer(from_custodian, to_custodian)
    );
    uint32_t to_custodian_id = require_get_custodian_id_with_permissions(
        to_custodian,
        get_custodian_to_flags_needed_for_transfer(from_custodian, to_custodian)
    );
    // end check permissions

    

    // start scope helpers pt 1
    t_item_balances to_item_balances = get_tbl_item_balances(to);
    t_custody_balances to_custody_balances = get_tbl_custody_balances(to);
    t_frozen_balances to_frozen_balances = get_tbl_frozen_balances(to);

    t_item_balances from_item_balances = get_tbl_item_balances(from);
    t_custody_balances from_custody_balances = get_tbl_custody_balances(from);
    t_frozen_balances from_frozen_balances = get_tbl_frozen_balances(from);
    
    //to item_balances are empty => no scope has been created yet
    bool no_previous_scope_item_balances = to_item_balances.begin() == to_item_balances.end();
    if (no_previous_scope_item_balances) {
        //A dummy item_balance is emplaced, which makes the scope_payer pay for the ram of the scope
        //This item_balance is later deleted again.
        //This action will therefore fail if the scope_payer didn't authorize the action
        to_item_balances.emplace(scope_payer, [&](auto &_item_balance) {
            _item_balance.item_id = ULLONG_MAX;
            _item_balance.status = 0;
            _item_balance.balance = 0;
            _item_balance.balance_in_custody = 0;
            _item_balance.balance_frozen = 0;
        });
    }

    //to custody_balances are empty => no scope has been created yet
    bool no_previous_scope_custody_balances = to_custody_balances.begin() == to_custody_balances.end();
    if (no_previous_scope_custody_balances) {
        //A dummy custody_balance is emplaced, which makes the scope_payer pay for the ram of the scope
        //This custody_balance is later deleted again.
        //This action will therefore fail if the scope_payer didn't authorize the action
        to_custody_balances.emplace(scope_payer, [&](auto &_custody_balance) {
            _custody_balance.item_id = ULLONG_MAX;
            _custody_balance.status = 0;
            _custody_balance.balance = 0;
            _custody_balance.balance_in_custody = 0;
            _custody_balance.balance_frozen = 0;
        });
    }

    //to frozen_balances are empty => no scope has been created yet
    bool no_previous_scope_frozen_balances = to_frozen_balances.begin() == to_frozen_balances.end();
    if (no_previous_scope_frozen_balances) {
        //A dummy frozen_balance is emplaced, which makes the scope_payer pay for the ram of the scope
        //This frozen_balance is later deleted again.
        //This action will therefore fail if the scope_payer didn't authorize the action
        to_frozen_balances.emplace(scope_payer, [&](auto &_frozen_balance) {
            _frozen_balance.item_id = ULLONG_MAX;
            _frozen_balance.status = 0;
            _frozen_balance.balance = 0;
            _frozen_balance.balance_in_custody = 0;
            _frozen_balance.balance_frozen = 0;
        });
    }
    // end scope helpers pt 1


    std::map <uint64_t, vector <uint64_t>> collection_to_item_ids_transferred = {};
    std::map <uint64_t, vector <uint64_t>> collection_to_item_amounts_transferred = {};
    int32_t index = 0;
    for (uint64_t item_id : item_ids) {
        uint64_t amount = amounts.at(index);
        auto item_balance_itr = from_item_balances.require_find(item_id,
            ("Sender doesn't own at least one of the provided item_balances (ID: " +
             to_string(item_id) + ")").c_str());
        check(amount>0,"cannot send 0 amount");
        check(item_balance_itr->balance>=amount,"not enough balance to sent this amount!");
        

        auto item_itr = tbl_items.require_find(item_balance_itr->item_id,"item does not exist");
        uint32_t item_config = (item_itr->item_config);
        uint32_t item_status = (item_balance_itr->status);

        check((item_config&ITEM_CONFIG_TRANSFERABLE)!=0,
            ("At least one item_balance isn't transferable (ID: " + to_string(item_id) + ")").c_str());

        check((item_config&ITEM_CONFIG_FROZEN)==0&&(item_status&ITEM_CONFIG_FROZEN)==0,
            ("At least one item_balance is frozen (ID: " + to_string(item_id) + ")").c_str());

        


        //This is needed for sending notifications later
        if (collection_to_item_ids_transferred.find(item_itr->collection_id) !=
            collection_to_item_ids_transferred.end()) {
            collection_to_item_ids_transferred[item_itr->collection_id].push_back(item_id);
            collection_to_item_amounts_transferred[item_itr->collection_id].push_back(amount);
        } else {
            collection_to_item_ids_transferred[item_itr->collection_id] = {item_id};
            collection_to_item_amounts_transferred[item_itr->collection_id] = {amount};
        }
        sub_from_user_balance(
            from,
            from_custodian,
            from_custodian_id,
            from_item_balances,
            from_custody_balances,
            from_frozen_balances,
            scope_payer,
            item_id,
            amount,
            can_use_liquid_and_custodian,
            max_unfreeze_iterations
        );
        add_to_user_balance(
            to,
            to_custodian,
            to_custodian_id,
            to_item_balances,
            to_custody_balances,
            to_frozen_balances,
            scope_payer,
            item_id,
            amount,
            unfreezes_at
        );

        index++;
    }

    if (no_previous_scope_item_balances) {
        to_item_balances.erase(to_item_balances.find(ULLONG_MAX));
    }
    if (no_previous_scope_frozen_balances) {
        to_frozen_balances.erase(to_frozen_balances.find(ULLONG_MAX));
    }
    if (no_previous_scope_custody_balances) {
        to_custody_balances.erase(to_custody_balances.find(ULLONG_MAX));
    }

    //Sending notifications
    for (const auto&[collection, item_ids_transferred] : collection_to_item_ids_transferred) {
        action(
            permission_level{get_self(), name("active")},
            get_self(),
            name("logtransfer"),
            make_tuple(authorizer, collection, from, to, from_custodian, to_custodian, item_ids_transferred, collection_to_item_amounts_transferred[collection], memo)
        ).send();
    }
}
void zswitems::internal_mint(
    name minter,
    name to,
    name to_custodian,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo,
    name scope_payer,
    uint32_t freeze_time
) {
    check(is_account(to), "ZSW: to account does not exist");
    check(minter.value != NULL_CUSTODIAN_NAME.value,"null custodian cannot mint items");


    check(item_ids.size() != 0, "item_ids needs to contain at least one id");
    check(item_ids.size() == amounts.size(), "item_ids should be the same size as amounts");

    check(memo.length() <= 256, "A transfer memo can only be 256 characters max");

    uint32_t cur_time_sec = eosio::current_time_point().sec_since_epoch();
    check(0xffffffff-freeze_time>cur_time_sec, "freeze time set to high, leads to overflow (set in the next 100 years)!");
    uint32_t unfreezes_at = freeze_time == 0?0:(freeze_time+cur_time_sec);


    // start check permissions

    uint128_t minter_perms = zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, minter);
    uint32_t to_custodian_id = require_get_custodian_id_with_permissions(to_custodian, 0);
    check(
        (minter_perms & ZSW_ITEMS_PERMS_AUTHORIZE_MINT_ITEM)!=0,
        "minter is not allowed to mint items"
    );
    if(to_custodian.value == NULL_CUSTODIAN_NAME.value){
        check(
            (minter_perms & ZSW_ITEMS_PERMS_AUTHORIZE_MINT_TO_NULL_CUSTODIAN)!=0,
            "minter is not allowed to mint items to the null custodian"
        );
    }else if(to_custodian.value != minter.value){
        check(
            (minter_perms & ZSW_ITEMS_PERMS_AUTHORIZE_MINT_TO_OTHER_CUSTODIANS)!=0,
            "authorizer is not allowed to mint to other custodians"
        );
    }
    // end check permissions

    vector <uint64_t> item_ids_copy = item_ids;
    std::sort(item_ids_copy.begin(), item_ids_copy.end());
    check(std::adjacent_find(item_ids_copy.begin(), item_ids_copy.end()) == item_ids_copy.end(),
        "Can't transfer the same item_balance multiple times");
    

    t_item_balances to_item_balances = get_tbl_item_balances(to);
    t_custody_balances to_custody_balances = get_tbl_custody_balances(to);
    t_frozen_balances to_frozen_balances = get_tbl_frozen_balances(to);
    
    //to item_balances are empty => no scope has been created yet
    bool no_previous_scope_item_balances = to_item_balances.begin() == to_item_balances.end();
    if (no_previous_scope_item_balances) {
        //A dummy item_balance is emplaced, which makes the scope_payer pay for the ram of the scope
        //This item_balance is later deleted again.
        //This action will therefore fail if the scope_payer didn't authorize the action
        to_item_balances.emplace(scope_payer, [&](auto &_item_balance) {
            _item_balance.item_id = ULLONG_MAX;
            _item_balance.status = 0;
            _item_balance.balance = 0;
            _item_balance.balance_in_custody = 0;
            _item_balance.balance_frozen = 0;
        });
    }

    //to custody_balances are empty => no scope has been created yet
    bool no_previous_scope_custody_balances = to_custody_balances.begin() == to_custody_balances.end();
    if (no_previous_scope_custody_balances) {
        //A dummy custody_balance is emplaced, which makes the scope_payer pay for the ram of the scope
        //This custody_balance is later deleted again.
        //This action will therefore fail if the scope_payer didn't authorize the action
        to_custody_balances.emplace(scope_payer, [&](auto &_custody_balance) {
            _custody_balance.item_id = ULLONG_MAX;
            _custody_balance.status = 0;
            _custody_balance.balance = 0;
            _custody_balance.balance_in_custody = 0;
            _custody_balance.balance_frozen = 0;
        });
    }

    //to frozen_balances are empty => no scope has been created yet
    bool no_previous_scope_frozen_balances = to_frozen_balances.begin() == to_frozen_balances.end();
    if (no_previous_scope_frozen_balances) {
        //A dummy frozen_balance is emplaced, which makes the scope_payer pay for the ram of the scope
        //This frozen_balance is later deleted again.
        //This action will therefore fail if the scope_payer didn't authorize the action
        to_frozen_balances.emplace(scope_payer, [&](auto &_frozen_balance) {
            _frozen_balance.item_id = ULLONG_MAX;
            _frozen_balance.status = 0;
            _frozen_balance.balance = 0;
            _frozen_balance.balance_in_custody = 0;
            _frozen_balance.balance_frozen = 0;
        });
    }

    std::map <uint64_t, vector <uint64_t>> collection_to_item_ids_minted = {};
    std::map <uint64_t, vector <uint64_t>> collection_to_item_amounts_minted = {};
    int32_t index = 0;
    for (uint64_t item_id : item_ids) {
        uint64_t amount = amounts.at(index);
        check(amount>0,"cannot send 0 amount");
        check((item_id & 0xffffffffff)==item_id,"item_id cannot be larger than 2^40-1");
        auto item_itr = tbl_items.require_find(item_id,"item does not exist");
        require_auth(item_itr->authorized_minter);
        uint32_t item_config = (item_itr->item_config);
        
        check((item_config&ITEM_CONFIG_FROZEN)==0,
            ("At least one item is frozen (ID: " + to_string(item_id) + ")").c_str());

        uint64_t new_supply = item_itr->total_supply + amount;
        check(item_itr->max_supply == 0 || new_supply <= item_itr->max_supply, "cannot mint more than max_supply!");

        tbl_items.modify(item_itr, minter, [&](auto &_item) {
            _item.total_supply = new_supply;
        });


        //This is needed for sending notifications later
        if (collection_to_item_ids_minted.find(item_itr->collection_id) !=
            collection_to_item_ids_minted.end()) {
            collection_to_item_ids_minted[item_itr->collection_id].push_back(item_id);
            collection_to_item_amounts_minted[item_itr->collection_id].push_back(amount);
        } else {
            collection_to_item_ids_minted[item_itr->collection_id] = {item_id};
            collection_to_item_amounts_minted[item_itr->collection_id] = {amount};
        }

        add_to_user_balance(
            to,
            to_custodian,
            to_custodian_id,
            to_item_balances,
            to_custody_balances,
            to_frozen_balances,
            scope_payer,
            item_id,
            amount,
            unfreezes_at
        );

        index++;
    }

    if (no_previous_scope_item_balances) {
        to_item_balances.erase(to_item_balances.find(ULLONG_MAX));
    }
    if (no_previous_scope_frozen_balances) {
        to_frozen_balances.erase(to_frozen_balances.find(ULLONG_MAX));
    }
    if (no_previous_scope_custody_balances) {
        to_custody_balances.erase(to_custody_balances.find(ULLONG_MAX));
    }
    //Sending notifications
    for (const auto&[collection, item_ids_minted] : collection_to_item_ids_minted) {
        action(
            permission_level{get_self(), name("active")},
            get_self(),
            name("logmint"),
            make_tuple(minter, collection, to, to_custodian, item_ids_minted, collection_to_item_amounts_minted[collection], memo)
        ).send();
    }
}
void zswitems::add_to_user_balance(
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
){
    check(amount>0,"cannot add 0 amount");
    
    auto to_itr = to_item_balances.find(item_id);
    uint64_t balance_in_custody_to_add = 0;//(custodian.value == NULL_CUSTODIAN_NAME.value)?0:amount;
    uint64_t balance_frozen_to_add = 0;//(unfreezes_at==0)?0:amount;

    if(unfreezes_at==0){
        if(custodian.value != NULL_CUSTODIAN_NAME.value){
            balance_in_custody_to_add = amount;
            uint64_t custody_balance_id = CREATE_CUSTODY_BALANCE_ID_BY_CUSTODIAN(custodian_id, item_id);
            auto to_custodian_itr = to_custody_balances.find(custody_balance_id);

            if(to_custodian_itr == to_custody_balances.end()){
                to_custody_balances.emplace(ram_payer, [&](auto &_custody_balance) {
                    _custody_balance.custody_balance_id = custody_balance_id;
                    _custody_balance.balance = amount;
                    _custody_balance.status = 0;
                });
            }else{
                to_custody_balances.modify(to_custodian_itr, ram_payer, [&](auto &_custody_balance) {
                    _custody_balance.balance = _custody_balance.balance + amount;
                });
            }
        }
    }else{
        balance_frozen_to_add = amount;
        auto frozen_custodian_index = to_frozen_balances.get_index<name("bycustodian")>();
        auto frozen_itr = frozen_custodian_index.find(CREATE_FROZEN_ID_BY_CUSTODIAN(custodian_id, item_id, unfreezes_at));

        if(frozen_itr == frozen_custodian_index.end()){
            uint64_t frozen_balance_id = to_frozen_balances.available_primary_key();
            to_frozen_balances.emplace(ram_payer, [&](auto &_frozen_balance) {
                _frozen_balance.frozen_balance_id = frozen_balance_id;
                _frozen_balance.balance = amount;
                _frozen_balance.custodian_id = custodian_id;
                _frozen_balance.unfreezes_at = unfreezes_at;
                _frozen_balance.item_id = item_id;
            });
        }else{
            frozen_custodian_index.modify(frozen_itr, ram_payer, [&](auto &_frozen_balance) {
                _frozen_balance.balance = _frozen_balance.balance + amount;
            });
        }
    }



    if(to_itr == to_item_balances.end()){
        to_item_balances.emplace(ram_payer, [&](auto &_item_balance) {
            _item_balance.item_id = item_id;
            _item_balance.status = 0;
            _item_balance.balance = amount;
            _item_balance.balance_in_custody = balance_in_custody_to_add;
            _item_balance.balance_frozen = balance_frozen_to_add;
        });
    }else{
        to_item_balances.modify(to_itr, ram_payer, [&](auto &_item_balance) {
            _item_balance.balance = _item_balance.balance + amount;
            _item_balance.balance_in_custody = _item_balance.balance_in_custody + balance_in_custody_to_add;
            _item_balance.balance_frozen = _item_balance.balance_frozen + balance_frozen_to_add;
        });
    }
}



void zswitems::sub_from_user_balance(
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
    
){
    check(amount>0,"cannot add 0 amount");
    uint32_t unfroze_total = unfreeze_up_to_amount(
        user,
        custodian_id,
        from_item_balances,
        from_custody_balances,
        from_frozen_balances,
        ram_payer,
        item_id,
        amount,
        max_unfreeze_iterations
    );
    if(can_use_liquid_and_custodian && unfroze_total<amount && custodian_id != NULL_CUSTODIAN_ID){
        unfroze_total += unfreeze_up_to_amount(
            user,
            NULL_CUSTODIAN_ID,
            from_item_balances,
            from_custody_balances,
            from_frozen_balances,
            ram_payer,
            item_id,
            amount ,
            max_unfreeze_iterations      
        );
    }
    
    auto from_itr = from_item_balances.require_find(item_id, "sender does not have this item!");
    uint64_t cur_balance = from_itr->balance;
    check(cur_balance >= amount, "sender does not have enough of the item to send!");
    
    uint64_t amount_to_remove = amount;
    bool can_use_null_custodian_actual = can_use_liquid_and_custodian || (custodian_id == NULL_CUSTODIAN_ID);

    
    if(custodian_id != NULL_CUSTODIAN_ID){
        uint64_t custody_balance_id = CREATE_CUSTODY_BALANCE_ID_BY_CUSTODIAN(custodian_id, item_id);
        auto custody_balance_itr = from_custody_balances.find(custody_balance_id);

        if(custody_balance_itr != from_custody_balances.end()){
            uint64_t cust_bal = custody_balance_itr->balance;
            if(cust_bal > amount){
                from_custody_balances.modify(custody_balance_itr, ram_payer, [&](auto &_custody_balance) {
                    _custody_balance.balance = _custody_balance.balance - amount;
                });
            }else{
                amount_to_remove -= cust_bal;
                from_custody_balances.erase(custody_balance_itr);
            }
            from_item_balances.modify(from_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.balance_in_custody = _item_balance.balance_in_custody - cust_bal;
                _item_balance.balance = _item_balance.balance - cust_bal;
            });
            from_itr = from_item_balances.require_find(item_id, "sender does not have this item!");
        }
    }
    cur_balance = from_itr->balance;
    uint64_t cur_balance_frozen = from_itr->balance_frozen;
    uint64_t cur_balance_in_custody = from_itr->balance_in_custody;
    uint64_t cur_pure_liquid_balance =cur_balance-(cur_balance_frozen+cur_balance_in_custody);

    check(
        amount_to_remove == 0 || (can_use_liquid_and_custodian && cur_pure_liquid_balance>=amount_to_remove),
        "sender insufficient item balance"
    );
    cur_balance -= amount_to_remove;
    cur_pure_liquid_balance -= amount_to_remove;
    if(cur_balance == 0){
        from_item_balances.erase(from_itr);
    }else{
        from_item_balances.modify(from_itr, ram_payer, [&](auto &_item_balance) {
            _item_balance.balance = _item_balance.balance - amount_to_remove;
        });
    }
}

uint64_t zswitems::unfreeze_up_to_amount(
    name user,
    uint32_t custodian_id,
    t_item_balances from_item_balances,
    t_custody_balances from_custody_balances,
    t_frozen_balances from_frozen_balances,
    name ram_payer,
    uint64_t item_id,
    uint64_t amount,
    uint32_t max_iterations
) {
    check(amount>0,"cannot unfreeze amount 0");
    uint32_t cur_time_sec = eosio::current_time_point().sec_since_epoch();
    auto frozen_cus_idx = from_custody_balances.get_index<name("bycustodian")>();
    uint128_t lower_bound = CREATE_FROZEN_ID_BY_CUSTODIAN(custodian_id, item_id, 0);
    
    auto frozen_itr = frozen_cus_idx.lower_bound(lower_bound);
    uint32_t unfrozen_amount = 0;
    while(max_iterations>0&&frozen_itr != frozen_cus_idx.end() && unfrozen_amount<amount && (frozen_itr->unfreezes_at) <= cur_time_sec){
        unfrozen_amount += frozen_itr->balance;
        frozen_cus_idx.erase(frozen_itr);
        max_iterations--;
    }
    if(unfrozen_amount != 0){
        auto item_balances_itr = from_item_balances.require_find(item_id, "item has no balance, this is impossible");
        

        if(custodian_id != 0){
            uint64_t custody_balance_id = CREATE_CUSTODY_BALANCE_ID_BY_CUSTODIAN(custodian_id, item_id);
            auto custody_bal_itr = from_custody_balances.find(custody_balance_id);

            if(custody_bal_itr == from_custody_balances.end()){
                from_custody_balances.emplace(ram_payer, [&](auto &_custody_balance) {
                    _custody_balance.custody_balance_id = custody_balance_id;
                    _custody_balance.balance = unfrozen_amount;
                    _custody_balance.status = 0;
                });
            }else{
                from_custody_balances.modify(custody_bal_itr, ram_payer, [&](auto &_custody_balance) {
                    _custody_balance.balance = _custody_balance.balance + unfrozen_amount;
                });
            }
            from_item_balances.modify(item_balances_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.frozen_balance = _frozen_balance.frozen_balance - unfrozen_amount;
                _item_balance.balance_in_custody = _item_balance.balance_in_custody + unfrozen_amount;
            });
        }else{
            from_item_balances.modify(item_balances_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.frozen_balance = _frozen_balance.frozen_balance - unfrozen_amount;
            });
        }
    }
    return unfrozen_amount;
}
/**
* Notifies all of a collection's notify accounts using require_recipient
*/
void zswitems::notify_collection_accounts(
    uint64_t collection_id
) {
    auto collection_itr = tbl_collections.require_find(collection_id,
        "No collection with this name exists");

    for (const name &notify_account : collection_itr->notify_accounts) {
        require_recipient(notify_account);
    }
}

/**
* Notifies all of a custodian's notify accounts using require_recipient
*/
void zswitems::notify_custodian_accounts(
    name custodian
) {
    auto custodian_itr = tbl_custodians.get_index<name("byname")>().require_find(custodian.value,
        "No custodian with this name exists");

    for (const name &notify_account : custodian_itr->notify_accounts) {
        require_recipient(notify_account);
    }
}


zswitems::t_item_balances zswitems::get_tbl_item_balances(name account) {
    return zswitems::t_item_balances(get_self(), account.value);
}
zswitems::t_frozen_balances zswitems::get_tbl_frozen_balances(name account) {
    return zswitems::t_frozen_balances(get_self(), account.value);
}
zswitems::t_custody_balances zswitems::get_tbl_custody_balances(name account) {
    return zswitems::t_custody_balances(get_self(), account.value);
}

uint32_t zswitems::require_get_custodian_id_with_permissions(name account, uint128_t permissions) {
    if(account.value == NULL_CUSTODIAN_NAME.value){
        // null can do all so no need to check permissions
        return NULL_CUSTODIAN_ID;
    }
    auto itr = tbl_custodians.require_find(account.value, "this user is not a custodian!");


    check(((itr->permissions) & permissions) == (permissions | CUSTODIAN_PERMS_ENABLED), "this user is missing the required custodian permissions for this action!");
    return itr->custodian_id;

}


