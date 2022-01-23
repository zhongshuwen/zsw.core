#include <eosio/eosio.hpp>
#include <zsw.items/zsw.items.hpp>
#include <zswinterfaces/zsw.perms-interface.hpp>
#include <zswinterfaces/zsw.items-interface.hpp>
#include <zswcoredata/checkformat.hpp>
using namespace eosio;

ACTION zswitems::init(name initializer) {
    require_auth(initializer);
    tbl_schemas.emplace(initializer, [&]( auto& _schema ) {
        _schema.schema_name = ""_n;
        _schema.format = {};
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
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo
) {
    require_auth(from);
    zswcore::require_transfer_authorizer(authorizer, from);
    require_recipient(from);
    require_recipient(to);
    internal_transfer(authorizer, from, to, item_ids, amounts, memo, from);
}
ACTION zswitems::mint(
    name minter,
    name to,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo
) {

    require_auth(minter);
    check(
        zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, minter) & ZSW_ITEMS_PERMS_AUTHORIZE_MINT_ITEM!=0,
        "authorizer is not allowed to create new schemas"
    );
    internal_mint(
        minter,
        to,
        item_ids,
        amounts,
        memo,
        minter
    );
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
        zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_SCHEMA!=0,
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
    require_auth(issuer_name);

    require_auth(authorizer);
    check(
        zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ISSUER!=0,
        "authorizer is not allowed to create new issuers"
    );


    auto itr = tbl_issuerstatus.find(issuer_name.value);
    check(itr == tbl_issuerstatus.end(), "this issuer user already exists!");

    tbl_issuerstatus.emplace(issuer_name, [&]( auto& _issuer_status ) {
        _issuer_status.issuer_name = issuer_name;
        _issuer_status.zsw_id = zsw_id;
        _issuer_status.alt_id = alt_id;
        _issuer_status.permissions = permissions;
        _issuer_status.status = status;
    });


}
ACTION zswitems::mkroyaltyusr(
    name authorizer,
    name newroyaltyusr,
    uint128_t zsw_id,
    uint128_t alt_id,
    uint32_t status
) {
    require_auth(newroyaltyusr);
    require_auth(authorizer);
    check(
        zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ROYALTY_USER!=0,
        "authorizer is not allowed to create royalty users"
    );


    auto itr = tbl_royaltyusers.find(newroyaltyusr.value);
    check(itr == tbl_royaltyusers.end(), "this royalty user already exists!");

    tbl_royaltyusers.emplace(newroyaltyusr, [&]( auto& _royalty_user ) {
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
    vector <name> authorized_accounts,
    ATTRIBUTE_MAP metadata
) {
    require_auth(creator);
    require_auth(issuing_platform);

    require_auth(authorizer);
    check(
        zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_COLLECTION!=0,
        "authorizer is not allowed to create collections"
    );

    auto itr = tbl_collections.find(collection_id);
    check(itr == tbl_collections.end(), "this collection id already exists!");

    check(schema_name.value==name("").value, "schemas/metadata not yet supported!");


    tbl_collections.emplace(creator, [&]( auto& _collection ) {
        _collection.collection_id = collection_id;
        _collection.creator = creator;
        _collection.issuing_platform = issuing_platform;
        _collection.zsw_code = zsw_code;
        _collection.collection_type = collection_type; 
        _collection.item_config = item_config;
        _collection.secondary_market_fee = secondary_market_fee; 
        _collection.primary_market_fee = primary_market_fee; 
        _collection.schema_name = schema_name;
        _collection.external_metadata_url = external_metadata_url;
        _collection.royalty_fee_collector = royalty_fee_collector;
        _collection.notify_accounts = notify_accounts;
        _collection.authorized_accounts = authorized_accounts;
        _collection.serialized_metadata = {};
    });
}


ACTION zswitems::mkitem(
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
) {

    require_auth(creator);
    require_auth(authorizer);
    require_auth(ram_payer);
    check(
        zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ITEM!=0,
        "authorizer is not allowed to create new items"
    );
    check(schema_name.value==name("").value, "schemas/metadata not yet supported!");



    auto itr = tbl_items.find(schema_name.value);
    check(itr == tbl_items.end(), "this item already exists!");

    tbl_items.emplace(creator, [&]( auto& _item ) {
        _item.item_id = item_id;
        _item.zsw_code = zsw_code;
        _item.item_config = item_config;
        _item.creator = creator;
        _item.ram_payer = ram_payer;
        _item.collection_id = collection_id;
        _item.max_supply = max_supply;
        _item.item_type = item_type;
        _item.schema_name = schema_name;
        _item.serialized_metadata = {};
        _item.external_metadata_url = external_metadata_url;
    });

}


ACTION zswitems::logtransfer(
    name authorizer,
    name collection_name,
    name from,
    name to,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo
) {
    require_auth(get_self());

    notify_collection_accounts(collection_name);
}
ACTION zswitems::logmint(
    name minter,
    name collection_name,
    name to,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo
) {
    require_auth(get_self());

    require_recipient(to);

    notify_collection_accounts(collection_name);
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
    name scope_payer
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
    

    t_item_balances from_item_balances = get_tbl_item_balances(from);
    t_item_balances to_item_balances = get_tbl_item_balances(to);

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
        
        uint64_t new_balance = item_balance_itr->balance - amount;

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

        //to item_balances are empty => no scope has been created yet
        bool no_previous_scope = to_item_balances.begin() == to_item_balances.end();
        if (no_previous_scope) {
            //A dummy item_balance is emplaced, which makes the scope_payer pay for the ram of the scope
            //This item_balance is later deleted again.
            //This action will therefore fail if the scope_payer didn't authorize the action
            to_item_balances.emplace(scope_payer, [&](auto &_item_balance) {
                _item_balance.item_id = ULLONG_MAX;
                _item_balance.status = 0;
                _item_balance.balance = 0;
            });
        }
        
        auto to_itr = to_item_balances.find(item_id);

        if(to_itr == to_item_balances.end()){
            to_item_balances.emplace(item_itr->ram_payer, [&](auto &_item_balance) {
                _item_balance.item_id = item_id;
                _item_balance.status = item_status | ITEM_BALANCE_STATUS_SECOND_HAND;
                _item_balance.balance = amount;
            });
        }else{
            to_item_balances.modify(to_itr, item_itr->ram_payer, [&](auto &_item_balance) {
                _item_balance.balance = _item_balance.balance + amount;
                _item_balance.status = _item_balance.status | ITEM_BALANCE_STATUS_SECOND_HAND;
            });
        }



        if (new_balance!=0) {
            from_item_balances.modify(item_balance_itr, same_payer, [&](auto &_item_balance) {
                _item_balance.balance = new_balance;
            });
        } else {
            from_item_balances.erase(item_balance_itr);
        }

        if (no_previous_scope) {
            to_item_balances.erase(to_item_balances.find(ULLONG_MAX));
        }

        index++;
    }

    //Sending notifications
    for (const auto&[collection, item_ids_transferred] : collection_to_item_ids_transferred) {
        action(
            permission_level{get_self(), name("active")},
            get_self(),
            name("logtransfer"),
            make_tuple(collection, from, to, item_ids_transferred, collection_to_item_amounts_transferred[collection], memo)
        ).send();
    }
}
void zswitems::internal_mint(
    name minter,
    name to,
    vector <uint64_t> item_ids,
    vector <uint64_t> amounts,
    string memo,
    name scope_payer
) {
    check(is_account(to), "to account does not exist");


    check(item_ids.size() != 0, "item_ids needs to contain at least one id");
    check(item_ids.size() == amounts.size(), "item_ids should be the same size as amounts");

    check(memo.length() <= 256, "A transfer memo can only be 256 characters max");

    vector <uint64_t> item_ids_copy = item_ids;
    std::sort(item_ids_copy.begin(), item_ids_copy.end());
    check(std::adjacent_find(item_ids_copy.begin(), item_ids_copy.end()) == item_ids_copy.end(),
        "Can't transfer the same item_balance multiple times");
    

    t_item_balances to_item_balances = get_tbl_item_balances(to);

    std::map <uint64_t, vector <uint64_t>> collection_to_item_ids_minted = {};
    std::map <uint64_t, vector <uint64_t>> collection_to_item_amounts_minted = {};
    int32_t index = 0;
    for (uint64_t item_id : item_ids) {
        uint64_t amount = amounts.at(index);
        check(amount>0,"cannot send 0 amount");
        auto item_itr = tbl_items.require_find(item_id,"item does not exist");
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

        //to item_balances are empty => no scope has been created yet
        bool no_previous_scope = to_item_balances.begin() == to_item_balances.end();
        if (no_previous_scope) {
            //A dummy item_balance is emplaced, which makes the scope_payer pay for the ram of the scope
            //This item_balance is later deleted again.
            //This action will therefore fail if the scope_payer didn't authorize the action
            to_item_balances.emplace(scope_payer, [&](auto &_item_balance) {
                _item_balance.item_id = ULLONG_MAX;
                _item_balance.status = 0;
                _item_balance.balance = 0;
            });
        }


        auto to_itr = to_item_balances.find(item_id);
        if(to_itr == to_item_balances.end()){
            to_item_balances.emplace(minter, [&](auto &_item_balance) {
                _item_balance.item_id = item_id;
                _item_balance.status = 0;
                _item_balance.balance = amount;
            });
        }else{
            to_item_balances.modify(to_itr, minter, [&](auto &_item_balance) {
                _item_balance.balance = _item_balance.balance + amount;
            });
        }



        if (no_previous_scope) {
            to_item_balances.erase(to_item_balances.find(ULLONG_MAX));
        }

        index++;
    }

    //Sending notifications
    for (const auto&[collection, item_ids_minted] : collection_to_item_ids_minted) {
        action(
            permission_level{get_self(), name("active")},
            get_self(),
            name("logmint"),
            make_tuple(minter, collection, to, item_ids_minted, collection_to_item_amounts_minted[collection], memo)
        ).send();
    }
}

/**
* Notifies all of a collection's notify accounts using require_recipient
*/
void zswitems::notify_collection_accounts(
    name collection_name
) {
    auto collection_itr = tbl_collections.require_find(collection_name.value,
        "No collection with this name exists");

    for (const name &notify_account : collection_itr->notify_accounts) {
        require_recipient(notify_account);
    }
}


zswitems::t_item_balances zswitems::get_tbl_item_balances(name account) {
    return zswitems::t_item_balances(get_self(), account.value);
}


