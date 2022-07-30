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

    zswperms::setperms_action setperms("zsw.perms"_n, {get_self(), "active"_n});

    setperms.send(
        ZSW_ITEMS_PERMS_SCOPE,
        ZSW_ITEMS_PERMS_SCOPE,
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

    auto issuerstatus_zswid_idx = tbl_issuerstatus.get_index<name("byzswid")>();
    auto issuerstatus_zswid_itr = issuerstatus_zswid_idx.find(zsw_id);
    check(issuerstatus_zswid_itr == issuerstatus_zswid_idx.end(), "a issuerstatus with this zsw_id already exists!");


    tbl_issuerstatus.emplace(authorizer, [&]( auto& _issuer_status ) {
        _issuer_status.issuer_name = issuer_name;
        _issuer_status.zsw_id = zsw_id;
        _issuer_status.alt_id = alt_id;
        _issuer_status.permissions = permissions;
        _issuer_status.status = status;
    });

    zswperms::addperms_action addperms("zsw.perms"_n, {get_self(), "active"_n});

    addperms.send(
        ZSW_ITEMS_PERMS_SCOPE,
        ZSW_ITEMS_PERMS_SCOPE,
        issuer_name,
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

    auto royaltyuser_zswid_idx = tbl_royaltyusers.get_index<name("byzswid")>();
    auto royaltyuser_zswid_itr = royaltyuser_zswid_idx.find(zsw_id);
    check(royaltyuser_zswid_itr == royaltyuser_zswid_idx.end(), "a royalty user with this zsw_id already exists!");


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
ACTION zswitems::dataintrface(name authorizer, ATTRIBUTE_MAP new_mutable_data){
    require_auth(authorizer);
}
ACTION zswitems::mkcollection(
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
    vector <name> authorized_minters,
    vector <name> notify_accounts,
    vector <name> authorized_mutable_data_editors,
    ATTRIBUTE_MAP metadata,
    std::string external_metadata_url
) {
    require_auth(creator);
    require_auth(issuing_platform);

    require_auth(authorizer);

    check (collection_type == 0, "collection_type == 0 only variant currently allowed");
    
    
    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_COLLECTION)!=0,
        "authorizer is not allowed to create collections"
    );

    check(
        collection_id == (uint64_t)(zsw_id & 0xffffffffffffffff),
        ("invalid collection_id, expecting "+to_string((uint64_t)(zsw_id & 0xffffffffffffffff))+"!").c_str()
    );


    check(
        secondary_market_fee <= MAX_PROFIT_SHARING_FEE_PRIMARY,
        "secondary_market_fee must be less than the maximum!"
    );
    check(
        primary_market_fee <= MAX_PROFIT_SHARING_FEE_PRIMARY,
        "primary_market_fee must be less than the maximum!"
    );
    check( max_supply > 0, "max_supply must be greater than 0");
    check( max_items > 0, "max_items must be greater than 0");
   
    vector<uint8_t> serialized_metadata;
    if(schema_name.value != name("").value){
        auto schema_itr = tbl_schemas.require_find(schema_name.value,"schema does not exist");
        serialized_metadata = serialize(metadata, schema_itr->format);
    }else{
        check(metadata.empty(), "metadata must be empty if a schema is not specified!");
        serialized_metadata = {};
    }




    check( authorized_minters.size() != 0, "authorized_minters cannot be empty!" );
    check( notify_accounts.size() == 0 || (item_config & ITEM_CONFIG_ALLOW_NOTIFY) != 0, "Can't add notify_accounts if allow_notify is false");

    for (auto itr = authorized_minters.begin(); itr != authorized_minters.end(); itr++) {
        check(is_account(*itr), string("authorized_minters: At least one account does not exist - " + itr->to_string()).c_str());
        check(std::find(authorized_minters.begin(), authorized_minters.end(), *itr) == itr,
            "You can't have duplicates in the authorized_minters");
    }
    for (auto itr = notify_accounts.begin(); itr != notify_accounts.end(); itr++) {
        check(is_account(*itr), string("notify_accounts: At least one account does not exist - " + itr->to_string()).c_str());
        check(std::find(notify_accounts.begin(), notify_accounts.end(), *itr) == itr,
            "You can't have duplicates in the notify_accounts");
    }



    if((item_config & ITEM_CONFIG_ALLOW_MUTABLE_DATA)!=0){
        check(authorized_mutable_data_editors.size() != 0, "authorized_mutable_data_editors cannot be empty if mutable data flag is set in item_config");

        for (auto itr = authorized_mutable_data_editors.begin(); itr != authorized_mutable_data_editors.end(); itr++) {
            check(is_account(*itr), string("authorized_mutable_data_editors: At least one account does not exist - " + itr->to_string()).c_str());
            check(std::find(authorized_mutable_data_editors.begin(), authorized_mutable_data_editors.end(), *itr) == itr,
                "You can't have duplicates in the authorized_mutable_data_editors");
        }
    }else{
        check(authorized_mutable_data_editors.size() == 0, "authorized_mutable_data_editors not allowed if mutable data flag is not set in item_config");
    }

    auto royalty_itr = tbl_royaltyusers.require_find(royalty_fee_collector.value,"royalty fee collector not yet approved");
    auto itr = tbl_collections.find(collection_id);
    check(itr == tbl_collections.end(), "this collection id already exists!");





    tbl_collections.emplace(issuing_platform, [&]( auto& _collection ) {
        _collection.zsw_id = zsw_id;
        _collection.collection_type = collection_type;
        _collection.creator = creator;
        _collection.issuing_platform = issuing_platform;
        _collection.item_config = item_config;
        _collection.secondary_market_fee = secondary_market_fee;
        _collection.primary_market_fee = primary_market_fee;
        _collection.royalty_fee_collector = royalty_fee_collector;
        _collection.issued_supply = 0;
        _collection.max_supply = max_supply;
        _collection.items_count = 0;
        _collection.max_supply_per_item = max_supply_per_item;
        _collection.max_items = max_items;
        _collection.schema_name = schema_name;
        _collection.authorized_minters = authorized_minters;
        _collection.notify_accounts = notify_accounts;
        _collection.authorized_mutable_data_editors = authorized_mutable_data_editors;
        _collection.serialized_metadata = serialized_metadata;
        _collection.external_metadata_url = external_metadata_url;
    });
}

ACTION zswitems::mkitemtpl(

    name authorizer,
    name creator,
    uint128_t zsw_id,
    uint64_t item_template_id,
    uint64_t collection_id,
    uint32_t item_type,
    name schema_name,
    ATTRIBUTE_MAP immutable_metadata,
    std::string item_external_metadata_url_template
) {
    require_auth(authorizer);
    require_auth(creator);

    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ITEM_TEMPLATE)!=0,
        "authorizer is not allowed to authorize the creation of item templates"
    );
    auto collection_itr = tbl_collections.require_find(collection_id, "collection does not exist!");
    auto authorized_minters = collection_itr->authorized_minters;

    check(
        std::find(authorized_minters.begin(), authorized_minters.end(), creator) != authorized_minters.end(),
        "creator is not an authorized_minter for this collection!"
    );
    check(
        item_template_id == (uint64_t)(zsw_id & 0xffffffffffffffff),
        ("invalid item_template_id, expecting "+to_string((uint64_t)(zsw_id & 0xffffffffffffffff))+"!").c_str()
    );


    auto item_templates_itr = tbl_item_templates.find(item_template_id);
    check(item_templates_itr == tbl_item_templates.end(), 
        ("item template with this id already exists (id=" + to_string(item_template_id) + ")").c_str()
    );

    //check that the item_type is not larger than the max currently supported value or that the template is in 20 bit mode
    check( ((item_type & ITEM_TYPE_ENFORCE_TPL_METADATA_MAX_ALT_ID_LAST_20_BITS_IN_TYPE) != 0) || item_type <= 0b111, "item_type is not currently supported!" );


    vector<uint8_t> serialized_immutable_metadata;
    if(schema_name.value != name("").value){
        auto schema_itr = tbl_schemas.require_find(schema_name.value,"schema does not exist");
        serialized_immutable_metadata = serialize(immutable_metadata, schema_itr->format);
        if((item_type&ITEM_TYPE_ENFORCE_TPL_METADATA_MAX_ALT_ID)!=0){
            auto max_alt_id_itr = immutable_metadata.find("max_alt_id");
            check(max_alt_id_itr != immutable_metadata.end(), "missing max_alt_id in template metadata");
            check(std::holds_alternative<uint64_t>(max_alt_id_itr->second),"max_alt_id is present in template metadata but not a uint64_t");
        }
    }else{
        check(immutable_metadata.empty(), "immutable_metadata must be empty if a schema is not specified!");
        check((item_type&ITEM_TYPE_ENFORCE_TPL_METADATA_MAX_ALT_ID)==0,"max_alt_id can not be restricted if there is no metadata");
        serialized_immutable_metadata = {};
    }



    tbl_item_templates.emplace(creator, [&]( auto& _item_template ) {
        _item_template.zsw_id = zsw_id;
        _item_template.collection_id = collection_id;
        _item_template.item_type = item_type;
        _item_template.schema_name = schema_name;
        _item_template.serialized_immutable_metadata = serialized_immutable_metadata;
        _item_template.item_external_metadata_url_template = item_external_metadata_url_template;
    });

    action(
        permission_level{get_self(), name("active")},
        get_self(),
        name("logmkitemtpl"),
        make_tuple(
            authorizer,
            creator,
            zsw_id,
            item_template_id,
            collection_id,
            item_type,
            schema_name,
            immutable_metadata,
            item_external_metadata_url_template
        )
    ).send();

}

ACTION zswitems::mkitem(
    name authorizer,
    name authorized_minter,
    uint64_t item_id,
    uint128_t zsw_id,
    uint32_t item_config,
    uint64_t item_template_id,
    uint64_t max_supply,
    name schema_name,
    ATTRIBUTE_MAP immutable_metadata,
    ATTRIBUTE_MAP mutable_metadata
) {

    require_auth(authorizer);
    require_auth(authorized_minter);
    check((item_id & 0xffffffffff)==item_id,"item_id cannot be larger than 2^40-1");
    check(((uint64_t)(zsw_id&0xffffffffff)) == item_id, 
        ("item id must be the first 40 bits of the zsw_id! (expecting: " + to_string(((uint64_t)(zsw_id&0xffffffffff)))+", got "+to_string(item_id) + ")").c_str()
    );

    check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorizer) & ZSW_ITEMS_PERMS_AUTHORIZE_CREATE_ITEM)!=0,
        "authorizer is not allowed to create new items"
    );

    check(max_supply>0,"max_supply must be > 0");

    auto items_itr = tbl_items.find(item_id);
    check(items_itr == tbl_items.end(), "this item already exists!");


    auto item_template_itr = tbl_item_templates.require_find(item_template_id, "item template does not exist!");
    check (
        (item_template_itr->schema_name.value == name("").value)||(item_template_itr->schema_name.value == schema_name.value),
        "an item's schema_name must match its item_template's (if it is set on the item_template)!"
    );
    uint64_t collection_id = item_template_itr->collection_id;
    auto collection_itr = tbl_collections.require_find(collection_id, "collection does not exist!");
    auto authorized_minters = collection_itr->authorized_minters;
    check( ((collection_itr->item_config)&item_config) == item_config, "invalid item_config for this collection!");
    check( collection_itr->max_supply_per_item==0 || collection_itr->max_supply_per_item>=max_supply,"invalid max_supply, must be less than the collection setting!");

    check(
        std::find(authorized_minters.begin(), authorized_minters.end(), authorized_minter) != authorized_minters.end(),
        "authorized_minter is not an authorized_minter for this collection!"
    );

    check(
        collection_itr->max_items == 0 || (collection_itr->max_items)>=(collection_itr->items_count+1),
        "this template has already maxed out its item count!"
    );
    tbl_collections.modify(collection_itr, authorized_minter, [&](auto &_collections) {
        _collections.items_count += 1;
    });
    



    vector<uint8_t> serialized_immutable_metadata;
    vector<uint8_t> serialized_mutable_metadata;

    //Needed for the log action
    ATTRIBUTE_MAP deserialized_template_data;

    if(schema_name.value != name("").value){
        auto schema_itr = tbl_schemas.require_find(schema_name.value,"schema does not exist");
        if(!immutable_metadata.empty()){
            serialized_immutable_metadata = serialize(immutable_metadata, schema_itr->format);
        }else{
            serialized_immutable_metadata={};
        }
        if(!mutable_metadata.empty()){
            serialized_mutable_metadata = serialize(mutable_metadata, schema_itr->format);
        }else{
            serialized_mutable_metadata={};
        }

        if (item_template_itr->schema_name.value != name("").value && !(item_template_itr->serialized_immutable_metadata.empty())) {
            deserialized_template_data = deserialize(
                item_template_itr->serialized_immutable_metadata,
                schema_itr->format
            );
        }else{
            deserialized_template_data = {};
        }
    }else{
        check(immutable_metadata.empty(), "immutable_metadata must be empty if a schema is not specified!");
        serialized_immutable_metadata = {};
        check(mutable_metadata.empty(), "mutable_metadata must be empty if a schema is not specified!");
        serialized_mutable_metadata={};

        if (item_template_itr->schema_name.value != name("").value && !(item_template_itr->serialized_immutable_metadata.empty())) {
            auto schema_itr = tbl_schemas.require_find((item_template_itr->schema_name).value,"item_template schema does not exist");
            deserialized_template_data = deserialize(
                item_template_itr->serialized_immutable_metadata,
                schema_itr->format
            );
        }else{
            deserialized_template_data = {};
        }
    }
    uint32_t item_tpl_item_type = item_template_itr->item_type;
    if((item_tpl_item_type&ITEM_TYPE_UNIQUE_ALT_ID_FOR_ITEM_TPL_ITEMS)!=0){
        // enforce unique high bits for item using item template
        auto tbl_item_tpl_alt_ids = get_tbl_item_tpl_alt_ids(item_template_id);
        check(tbl_item_tpl_alt_ids.find(GET_ITEM_ZSW_ID_ALT_ID(zsw_id)) == tbl_item_tpl_alt_ids.end(), "this item already exists in this template!");

        tbl_item_tpl_alt_ids.emplace(authorized_minter, [&]( auto& _item_tpl_alt_ids ) {
            _item_tpl_alt_ids.zsw_id = zsw_id;
        });
    }
    if((item_tpl_item_type&ITEM_TYPE_ENFORCE_TPL_METADATA_MAX_ALT_ID)!=0){
        // enforce tpl max_alt_id
        auto max_alt_id_itr = deserialized_template_data.find("max_alt_id");
        check(max_alt_id_itr != deserialized_template_data.end(), "missing max_alt_id in template metadata");
        check(std::holds_alternative<uint64_t>(max_alt_id_itr->second),"max_alt_id is present in template metadata but not a uint64_t");
        check(GET_ITEM_ZSW_ID_ALT_ID(zsw_id)<=std::get<uint64_t>(max_alt_id_itr->second),"item alt id exceeds max_alt_id");
    }
    if((item_tpl_item_type&ITEM_TYPE_ENFORCE_TPL_METADATA_MAX_ALT_ID_LAST_20_BITS_IN_TYPE)!=0){
        check(GET_ITEM_ZSW_ID_ALT_ID(zsw_id)<=((item_tpl_item_type>>12)&0xfffff),"item alt id exceeds max_alt_id");
    }


    tbl_items.emplace(authorized_minter, [&]( auto& _item ) {
        _item.zsw_id = zsw_id;
        _item.item_config = item_config;
        _item.item_template_id = item_template_id;
        _item.collection_id = collection_id;
        _item.issued_supply = 0;
        _item.max_supply = max_supply;
        _item.schema_name = schema_name;
        _item.serialized_immutable_metadata = serialized_immutable_metadata;
        _item.serialized_mutable_metadata = serialized_mutable_metadata;
    });

    action(
        permission_level{get_self(), name("active")},
        get_self(),
        name("logmkitem"),
        make_tuple(
            authorizer,
            authorized_minter,
            item_id,
            zsw_id,
            item_config,
            item_template_id,
            max_supply,
            schema_name,
            collection_id,
            immutable_metadata,
            mutable_metadata,
            deserialized_template_data
        )
    ).send();
}


ACTION zswitems::setitemdata(
       name authorized_editor,
       uint64_t item_id,
       ATTRIBUTE_MAP new_mutable_data
){
    require_auth(authorized_editor);
    eosio::check(
        (zswcore::get_zsw_perm_bits(ZSW_ITEMS_PERMS_SCOPE, authorized_editor) & ZSW_ITEMS_PERMS_AUTHORIZE_MODIFY_ITEM_METADATA)!=0,
        "authorized_editor is not allowed to modify metadata"
    );
    auto item_itr = tbl_items.require_find(item_id,"item does not exist");
    auto collection_itr = tbl_collections.require_find(item_itr->collection_id, "collection does not exist");
    check(
        (((collection_itr->item_config) & ITEM_CONFIG_ALLOW_MUTABLE_DATA ) != 0),
        "collection does not have mutable data enabled!"
    );
    check(
        (((item_itr->item_config) & ITEM_CONFIG_ALLOW_MUTABLE_DATA ) != 0),
        "item does not have mutable data enabled!"
    );
    auto authorized_mutable_data_editors = collection_itr->authorized_mutable_data_editors;
    check(
        std::find(authorized_mutable_data_editors.begin(), authorized_mutable_data_editors.end(), authorized_editor) != authorized_mutable_data_editors.end(),
        "user is not an authorized mutable data editor for this collection!"
    );
    check((item_itr->schema_name ).value!= name("").value,"schema cannot be empty for editing mutable data");

    auto schema_itr = tbl_schemas.require_find((item_itr->schema_name).value,"schema does not exist");

    ATTRIBUTE_MAP deserialized_old_data = deserialize(
        item_itr->serialized_mutable_metadata,
        schema_itr->format
    );

    action(
        permission_level{get_self(), name("active")},
        get_self(),
        name("logsetdata"),
        make_tuple(authorized_editor, item_id, item_itr->collection_id, deserialized_old_data, new_mutable_data)
    ).send();


    tbl_items.modify(item_itr, authorized_editor, [&](auto &_item) {
        _item.serialized_mutable_metadata = serialize(new_mutable_data, schema_itr->format);
    });

    


}

ACTION zswitems::logsetdata(
       name authorized_editor,
       uint64_t item_id,
       uint64_t collection_id,
       ATTRIBUTE_MAP old_data,
       ATTRIBUTE_MAP new_data
) {
    require_auth(get_self());

    notify_collection_accounts(collection_id);
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

ACTION zswitems::logmkitemtpl(
      name authorizer,
      name creator,
      uint128_t zsw_id,
      uint64_t item_template_id,
      uint64_t collection_id,
      uint32_t item_type,
      name schema_name,
      ATTRIBUTE_MAP immutable_metadata,
      std::string item_external_metadata_url_templat
){
    require_auth(get_self());
    notify_collection_accounts(collection_id);
}


ACTION zswitems::logmkitem(
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
    ATTRIBUTE_MAP immutable_template_data
){
    require_auth(get_self());
    notify_collection_accounts(collection_id);
}
ACTION zswitems::logtransfer(
    name authorizer,
    uint64_t collection_id,
    name collection_id_as_name,
    name from,
    name to,
    name from_custodian,
    name to_custodian,
    vector <uint64_t> item_ids,
    vector <uint64_t> item_template_ids,
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
    name collection_id_as_name,
    name to,
    name to_custodian,
    vector <uint64_t> item_ids,
    vector <uint64_t> item_template_ids,
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



void zswitems::add_to_user_balance(
    name user,
    name custodian,
    uint64_t custodian_user_pair_id,
    name ram_payer,
    uint64_t item_id,
    uint64_t amount,
    uint32_t unfreezes_at
){
    check((unfreezes_at&0xffffff)==unfreezes_at,"unfreezes_at must be <= 16777215 minutes!");
    check(amount>0,"amount must be > 0");
    uint32_t cur_time = get_current_time_minutes();
    unfreezes_at = unfreezes_at>cur_time?unfreezes_at:0;

    bool is_to_null_custodian = custodian.value == NULL_CUSTODIAN_NAME.value;
    bool needs_freeze = unfreezes_at>cur_time;
    

    auto tbl_item_balances = get_tbl_item_balances(user);

    auto item_balance_itr = tbl_item_balances.find(item_id);
    if(item_balance_itr == tbl_item_balances.end()){
        tbl_item_balances.emplace(ram_payer, [&](auto &_item_balance) {
            _item_balance.item_id = item_id;
            _item_balance.status = 0;
            if(is_to_null_custodian && !needs_freeze){
                _item_balance.active_custodian_pairs = {};
                _item_balance.balance_normal_liquid = amount;
                _item_balance.balance_frozen = 0;
                _item_balance.balance_in_custody_liquid = 0;
            }else{
                _item_balance.balance_normal_liquid = 0;
                _item_balance.balance_frozen = (needs_freeze)?amount:0;
                _item_balance.balance_in_custody_liquid = (needs_freeze)?0:amount;
                _item_balance.active_custodian_pairs = {custodian_user_pair_id};
            }
        });
    }else{
        check((item_balance_itr->status & ITEM_CONFIG_FROZEN) == 0,"item balance is frozen");
        if(is_to_null_custodian && !needs_freeze){
            tbl_item_balances.modify(item_balance_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.balance_normal_liquid += amount;
            });

        }else if(needs_freeze){
            tbl_item_balances.modify(item_balance_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.balance_frozen += amount;
                _item_balance.active_custodian_pairs = ensure_in_list(_item_balance.active_custodian_pairs, custodian_user_pair_id);
            });
            
        }else{
            tbl_item_balances.modify(item_balance_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.balance_in_custody_liquid += amount;
                _item_balance.active_custodian_pairs = ensure_in_list(_item_balance.active_custodian_pairs, custodian_user_pair_id);
            });
        }
    }
    if(!is_to_null_custodian || needs_freeze){
        auto tbl_frozen_balances = get_tbl_frozen_balances(custodian_user_pair_id);
        uint64_t frozen_balance_id = CREATE_FROZEN_BALANCE_ID(item_id, unfreezes_at);
        auto frozen_balances_itr = tbl_frozen_balances.find(frozen_balance_id);
        if(frozen_balances_itr == tbl_frozen_balances.end()){
            tbl_frozen_balances.emplace(ram_payer, [&](auto &_frozen_balance) {
                _frozen_balance.frozen_balance_id = frozen_balance_id;
                _frozen_balance.balance = amount;
                _frozen_balance.status = 0;
            });
        }else{
            tbl_frozen_balances.modify(frozen_balances_itr, ram_payer, [&](auto &_frozen_balance) {
                _frozen_balance.balance += amount;
            });
        }
    }
}

uint64_t zswitems::unfreeze_amount(
    uint64_t custodian_user_pair_id,
    name ram_payer,
    uint64_t item_id,
    uint64_t target_amount,
    uint32_t max_iterations
) {

    uint32_t cur_time = get_current_time_minutes();

    auto tbl_frozen_balances = get_tbl_frozen_balances(custodian_user_pair_id);
    uint64_t lower_bound = CREATE_FROZEN_BALANCE_ID(item_id, 1);
    uint64_t upper_bound = CREATE_FROZEN_BALANCE_ID(item_id, cur_time);
    uint64_t unfrozen_amount = 0;    
    auto frozen_itr = tbl_frozen_balances.lower_bound(lower_bound);
    while(max_iterations>0&&frozen_itr != tbl_frozen_balances.end() && unfrozen_amount<target_amount && (frozen_itr->frozen_balance_id) <= upper_bound){
        unfrozen_amount += frozen_itr->balance;
        frozen_itr = tbl_frozen_balances.erase(frozen_itr);
        max_iterations--;
    }




    return unfrozen_amount;


}

void zswitems::sub_from_user_balance(
    name user,
    name custodian,
    uint64_t custodian_user_pair_id,
    name ram_payer,
    uint64_t item_id,
    uint64_t amount,
    bool can_use_liquid_and_custodian,
    uint32_t max_unfreeze_iterations
){
    check(amount>0,"amount must be > 0");
    uint32_t cur_time = get_current_time_minutes();

    bool is_from_null_custodian = custodian.value == NULL_CUSTODIAN_NAME.value;
    auto tbl_item_balances = get_tbl_item_balances(user);

    auto item_balance_itr = tbl_item_balances.require_find(item_id, "user has insufficient balance!");
    check(
        add_no_overflow(add_no_overflow(item_balance_itr->balance_normal_liquid, item_balance_itr->balance_frozen), item_balance_itr->balance_in_custody_liquid) >= amount,
        "user has insufficient balance!"
    );

    if(is_from_null_custodian){
        if(item_balance_itr->balance_normal_liquid>=amount){
            tbl_item_balances.modify(item_balance_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.balance_normal_liquid -= amount;
            });
        }else{
            uint64_t unfrozen_amount = unfreeze_amount(
                custodian_user_pair_id,
                ram_payer,
                item_id,
                amount,
                max_unfreeze_iterations
            );
            check(item_balance_itr->balance_frozen >= unfrozen_amount, "unfroze calculation error");
            uint64_t new_liquid = add_no_overflow(unfrozen_amount, item_balance_itr->balance_normal_liquid);
            check(new_liquid >= amount, "user has insufficient liquid balance");
            uint64_t new_liquid_post_sub_balance = new_liquid - amount;
            if(new_liquid_post_sub_balance == 0 && item_balance_itr->balance_frozen == 0 && item_balance_itr->balance_in_custody_liquid == 0){
                tbl_item_balances.erase(item_balance_itr);
            }else{
                tbl_item_balances.modify(item_balance_itr, ram_payer, [&](auto &_item_balance) {
                    _item_balance.balance_normal_liquid = new_liquid_post_sub_balance;
                    _item_balance.balance_frozen -= unfrozen_amount;
                });
            }
        }
    }else{
        auto tbl_frozen_balances = get_tbl_frozen_balances(custodian_user_pair_id);
        uint64_t frozen_balance_id_base = CREATE_FROZEN_BALANCE_ID(item_id, 0);

        auto frozen_balance_itr = tbl_frozen_balances.find(frozen_balance_id_base);
        bool has_existing_cf_base_balance = frozen_balance_itr != tbl_frozen_balances.end();
        uint64_t cf_start_base_balance = has_existing_cf_base_balance?frozen_balance_itr->balance:0;
        uint64_t cf_base_balance = cf_start_base_balance;
        
        uint64_t cf_unfroze_amount = 0;
        uint64_t cf_liquid_normal_remove_amount = 0;
        if(cf_base_balance<amount){
            cf_unfroze_amount =  unfreeze_amount(
                custodian_user_pair_id,
                ram_payer,
                item_id,
                amount,
                max_unfreeze_iterations
            );
            cf_base_balance+=cf_unfroze_amount;
            if(cf_base_balance<amount && can_use_liquid_and_custodian){
                check(item_balance_itr->balance_normal_liquid >= (amount-cf_base_balance),"insufficient user balance");
                cf_liquid_normal_remove_amount = amount-cf_base_balance;
                cf_base_balance+=cf_liquid_normal_remove_amount;
            }
        }
        check(cf_base_balance>=amount, "insufficient user balance");
        uint64_t post_normal_cf_base_balance = (cf_base_balance) - (amount-cf_liquid_normal_remove_amount);

        uint64_t item_new_balance_frozen = item_balance_itr->balance_frozen-cf_unfroze_amount;
        uint64_t item_new_balance_in_custody_liquid = (cf_unfroze_amount+item_balance_itr->balance_in_custody_liquid)-(amount-cf_liquid_normal_remove_amount);
        uint64_t item_new_balance_normal_liquid = item_balance_itr->balance_normal_liquid - cf_liquid_normal_remove_amount;
        if(post_normal_cf_base_balance == 0){
            if(has_existing_cf_base_balance){
                tbl_frozen_balances.erase(frozen_balance_itr);
            }
        }else{
            if(has_existing_cf_base_balance){
                tbl_frozen_balances.modify(frozen_balance_itr, ram_payer, [&](auto &_item_balance) {
                    _item_balance.balance = post_normal_cf_base_balance;
                });
            }else{
                tbl_frozen_balances.emplace(ram_payer, [&](auto &_frozen_balance) {
                    _frozen_balance.frozen_balance_id = frozen_balance_id_base;
                    _frozen_balance.balance = post_normal_cf_base_balance;
                    _frozen_balance.status = 0;
                });
            }
        }
        if(item_new_balance_frozen == 0 && item_new_balance_in_custody_liquid == 0 && item_new_balance_normal_liquid == 0){
            tbl_item_balances.erase(item_balance_itr);
        }else{
            tbl_item_balances.modify(item_balance_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.balance_normal_liquid = item_new_balance_normal_liquid;
                _item_balance.balance_frozen = item_new_balance_frozen;
                _item_balance.balance_in_custody_liquid = item_new_balance_in_custody_liquid;
            });
        }
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
   ){
       require_auth(authorizer);
    check(is_account(to), "to account does not exist");

    //allow transfers to/from the same account only if it is a new custodian
    check(from != to || from_custodian != to_custodian, "Can't transfer item_balances to yourself");

    check(item_ids.size() != 0, "item_ids needs to contain at least one id");
    check(item_ids.size() == amounts.size(), "item_ids should be the same size as amounts");

    check(memo.length() <= 256, "A transfer memo can only be 256 characters max");

    vector <uint64_t> item_ids_copy = item_ids;
    std::sort(item_ids_copy.begin(), item_ids_copy.end());
    check(std::adjacent_find(item_ids_copy.begin(), item_ids_copy.end()) == item_ids_copy.end(),
        "Can't transfer the same item_balance multiple times");
    
    uint32_t cur_time_min = get_current_time_minutes();
    uint32_t unfreezes_at = freeze_time == 0?0:(freeze_time+cur_time_min);

    check((0xffffff&unfreezes_at)==unfreezes_at && (unfreezes_at==0||unfreezes_at>cur_time_min),"invalid freeze time");
    
    
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


    std::map <uint64_t, vector <uint64_t>> collection_to_item_ids_transferred = {};
    std::map <uint64_t, vector <uint64_t>> collection_to_item_template_ids_transferred = {};
    std::map <uint64_t, vector <uint64_t>> collection_to_item_amounts_transferred = {}; 
    uint64_t from_custodian_user_pair_id = get_custodian_user_pair_id(scope_payer, from_custodian, from);
    uint64_t to_custodian_user_pair_id = get_custodian_user_pair_id(scope_payer, to_custodian, to);

    int32_t index = 0;
    for (uint64_t item_id : item_ids) {
        check((item_id & 0xffffffffff)==item_id,"item_id cannot be larger than 2^40-1");
        auto item_itr = tbl_items.require_find(item_id,"item does not exist");
        uint64_t amount = amounts.at(index);
        check(amount>0,"cannot send 0 amount");
        
        uint32_t item_config = (item_itr->item_config);

        check((item_config&ITEM_CONFIG_TRANSFERABLE)!=0,
            ("At least one item_balance isn't transferable (ID: " + to_string(item_id) + ")").c_str());

        check((item_config&ITEM_CONFIG_FROZEN)==0,
            ("At least one item_balance is frozen (ID: " + to_string(item_id) + ")").c_str());

        


        //This is needed for sending notifications later
        if (collection_to_item_ids_transferred.find(item_itr->collection_id) !=
            collection_to_item_ids_transferred.end()) {
            collection_to_item_ids_transferred[item_itr->collection_id].push_back(item_id);
            collection_to_item_template_ids_transferred[item_itr->collection_id].push_back(item_itr->item_template_id);
            collection_to_item_amounts_transferred[item_itr->collection_id].push_back(amount);
        } else {
            collection_to_item_ids_transferred[item_itr->collection_id] = {item_id};
            collection_to_item_ids_transferred[item_itr->collection_id] = {item_id};
            collection_to_item_template_ids_transferred[item_itr->collection_id] = {item_itr->item_template_id};
            collection_to_item_amounts_transferred[item_itr->collection_id] = {amount};
        }
        sub_from_user_balance(
            from,
            from_custodian,
            from_custodian_user_pair_id,
            scope_payer,
            item_id,
            amount,
            can_use_liquid_and_custodian,
            max_unfreeze_iterations
        );
        add_to_user_balance(
            to,
            to_custodian,
            to_custodian_user_pair_id,
            scope_payer,
            item_id,
            amount,
            unfreezes_at
        );

        index++;
    }

    //Sending notifications
    for (const auto&[collection, item_ids_transferred] : collection_to_item_ids_transferred) {

        action(
            permission_level{get_self(), name("active")},
            get_self(),
            name("logtransfer"),
            make_tuple(authorizer, collection, name(collection),from, to, from_custodian, to_custodian, item_ids_transferred, collection_to_item_template_ids_transferred[collection], collection_to_item_amounts_transferred[collection], memo)
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


    uint32_t cur_time_min = get_current_time_minutes();
    uint32_t unfreezes_at = freeze_time == 0?0:(freeze_time+cur_time_min);

    check((0xffffff&unfreezes_at)==unfreezes_at && (unfreezes_at==0||unfreezes_at>cur_time_min),"invalid freeze time");
    

    

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
    }else if(to_custodian.value == ZSW_CUSTODIAN_NAME.value){
        check(
            (minter_perms & ZSW_ITEMS_PERMS_AUTHORIZE_MINT_TO_OTHER_CUSTODIANS)!=0 ||
            (minter_perms & ZSW_ITEMS_PERMS_AUTHORIZE_MINT_TO_ZSW_CUSTODIAN)!=0,
            "authorizer is not allowed to mint to other/zsw custodians"
        );
    }else if(to_custodian.value != minter.value){
        check(
            (minter_perms & ZSW_ITEMS_PERMS_AUTHORIZE_MINT_TO_OTHER_CUSTODIANS)!=0,
            "authorizer is not allowed to mint to other custodians"
        );
    }
    // end check permissions
    uint64_t to_custodian_user_pair_id = get_custodian_user_pair_id(scope_payer, to_custodian, to);

    vector <uint64_t> item_ids_copy = item_ids;
    std::sort(item_ids_copy.begin(), item_ids_copy.end());
    check(std::adjacent_find(item_ids_copy.begin(), item_ids_copy.end()) == item_ids_copy.end(),
        "Can't transfer the same item_balance multiple times");
    

    std::map <uint64_t, vector <uint64_t>> collection_to_item_ids_transferred = {};
    std::map <uint64_t, vector <uint64_t>> collection_to_item_template_ids_transferred = {};
    std::map <uint64_t, vector <uint64_t>> collection_to_item_amounts_transferred = {};
    std::map <uint64_t, uint64_t> collection_id_minted_count ={};
    int32_t index = 0;
    for (uint64_t item_id : item_ids) {
        uint64_t amount = amounts.at(index);
        check(amount>0,"cannot send 0 amount");
        check((item_id & 0xffffffffff)==item_id,"item_id cannot be larger than 2^40-1");
        auto item_itr = tbl_items.require_find(item_id,"item does not exist");
        
        uint64_t new_supply = item_itr->issued_supply + amount;
        check(item_itr->max_supply == 0 || new_supply <= item_itr->max_supply, "cannot mint more than max_supply!");

        tbl_items.modify(item_itr, minter, [&](auto &_item) {
            _item.issued_supply = new_supply;
        });

        


        uint32_t item_config = (item_itr->item_config);

        check((item_config&ITEM_CONFIG_TRANSFERABLE)!=0,
            ("At least one item_balance isn't transferable (ID: " + to_string(item_id) + ")").c_str());

        check((item_config&ITEM_CONFIG_FROZEN)==0,
            ("At least one item_balance is frozen (ID: " + to_string(item_id) + ")").c_str());
        uint64_t collection_id = item_itr->collection_id;

        


        //This is needed for sending notifications later
        if (collection_to_item_ids_transferred.find(collection_id) !=
            collection_to_item_ids_transferred.end()) {
            collection_to_item_ids_transferred[collection_id].push_back(item_id);
            collection_to_item_template_ids_transferred[item_itr->collection_id].push_back(item_itr->item_template_id);
            collection_to_item_amounts_transferred[collection_id].push_back(amount);
            
            collection_id_minted_count[collection_id] += amount;
        } else {
            collection_to_item_ids_transferred[collection_id] = {item_id};
            collection_to_item_template_ids_transferred[collection_id] = {item_itr->item_template_id};
            collection_to_item_amounts_transferred[collection_id] = {amount};
            collection_id_minted_count[collection_id] = amount;
        }
        add_to_user_balance(
            to,
            to_custodian,
            to_custodian_user_pair_id,
            scope_payer,
            item_id,
            amount,
            unfreezes_at
        );

        index++;
    }

    //Sending notifications
    for (const auto&[collection, item_ids_minted] : collection_to_item_ids_transferred) {
        auto collection_itr = tbl_collections.require_find(collection, "invalid collection!");
        uint64_t new_collection_supply = add_no_overflow(collection_itr->issued_supply,collection_id_minted_count[collection]);
        check(new_collection_supply<=collection_itr->max_supply,"exceeds collection max supply!");
        auto collection_authorized_minters = collection_itr->authorized_minters;

        tbl_collections.modify(collection_itr, scope_payer, [&](auto &_collection) {
            _collection.issued_supply = new_collection_supply;
        });

        check(
            std::find(collection_authorized_minters.begin(), collection_authorized_minters.end(), minter) != collection_authorized_minters.end(),
            "user is not authorized to mint some of the items!"
        );
        action(
            permission_level{get_self(), name("active")},
            get_self(),
            name("logmint"),
            make_tuple(minter, collection, name(collection), to, to_custodian, item_ids_minted, collection_to_item_template_ids_transferred[collection], collection_to_item_amounts_transferred[collection], memo)
        ).send();
    }
}
/*
void zswitems::add_to_user_balance(
    name user,
    name custodian,
    uint32_t custodian_id,
    name ram_payer,
    uint64_t item_id,
    uint64_t amount,
    uint32_t unfreezes_at
){
    check(amount>0,"cannot add 0 amount");
    t_item_balances to_item_balances = get_tbl_item_balances(user);
    t_custody_balances to_custody_balances = get_tbl_custody_balances(user);
    t_frozen_balances to_frozen_balances = get_tbl_frozen_balances(user);
    
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
*/

/*
void zswitems::sub_from_user_balance(
    name user,
    name custodian,
    uint64_t custodian_user_pair_id,
    name ram_payer,
    uint64_t item_id,
    uint64_t amount,
    bool can_use_liquid_and_custodian,
    uint32_t max_unfreeze_iterations
    
){
    check(amount>0,"cannot add 0 amount");
    
    t_item_balances from_item_balances = get_tbl_item_balances(user);
    t_custody_balances from_custody_balances = get_tbl_custody_balances(user);
    t_frozen_balances from_frozen_balances = get_tbl_frozen_balances(user);
    uint32_t unfroze_total = unfreeze_up_to_amount(
        user,
        custodian_id,
        ram_payer,
        item_id,
        amount,
        max_unfreeze_iterations
    );
    if(can_use_liquid_and_custodian && unfroze_total<amount && custodian_id != NULL_CUSTODIAN_ID){
        unfroze_total += unfreeze_up_to_amount(
            user,
            NULL_CUSTODIAN_ID,
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
                from_item_balances.modify(from_itr, ram_payer, [&](auto &_item_balance) {
                    _item_balance.balance_in_custody = _item_balance.balance_in_custody - amount;
                    _item_balance.balance = _item_balance.balance - amount;
                });
                amount_to_remove = 0;
            }else{
                amount_to_remove -= cust_bal;
                from_custody_balances.erase(custody_balance_itr);
                from_item_balances.modify(from_itr, ram_payer, [&](auto &_item_balance) {
                    _item_balance.balance_in_custody = _item_balance.balance_in_custody - cust_bal;
                    _item_balance.balance = _item_balance.balance - cust_bal;
                });
            }
            
        }
    }
    from_itr = from_item_balances.require_find(item_id, "sender does not have this item!");
    cur_balance = from_itr->balance;
    uint64_t cur_balance_frozen = from_itr->balance_frozen;
    uint64_t cur_balance_in_custody = from_itr->balance_in_custody;
    check(cur_balance >= (cur_balance_frozen+cur_balance_in_custody),"overflow in frozen/custody");
    uint64_t cur_pure_liquid_balance =cur_balance-(cur_balance_frozen+cur_balance_in_custody);

    check(
        amount_to_remove == 0 || (can_use_liquid_and_custodian && cur_pure_liquid_balance>=amount_to_remove && cur_balance >= amount_to_remove),
        "sender insufficient item balance"
    );
    cur_balance -= amount_to_remove;
    if(cur_balance == 0){
        from_item_balances.erase(from_itr);
    }else if(amount_to_remove!=0){
        from_item_balances.modify(from_itr, ram_payer, [&](auto &_item_balance) {
            _item_balance.balance = _item_balance.balance - amount_to_remove;
        });
    }
}
*/

/*
uint64_t zswitems::unfreeze_up_to_amount(
    name user,
    uint32_t custodian_id,
    name ram_payer,
    uint64_t item_id,
    uint64_t amount,
    uint32_t max_iterations
) {
    check(amount>0,"cannot unfreeze amount 0");
    t_item_balances from_item_balances = get_tbl_item_balances(user);
    t_custody_balances from_custody_balances = get_tbl_custody_balances(user);
    t_frozen_balances from_frozen_balances = get_tbl_frozen_balances(user);
    uint32_t cur_time_sec = eosio::current_time_point().sec_since_epoch();
    auto frozen_cus_idx = from_frozen_balances.get_index<name("bycustodian")>();
    uint128_t lower_bound = CREATE_FROZEN_ID_BY_CUSTODIAN(custodian_id, item_id, 0);
    
    auto frozen_itr = frozen_cus_idx.lower_bound(lower_bound);
    uint32_t unfrozen_amount = 0;
    while(max_iterations>0&&frozen_itr != frozen_cus_idx.end() && unfrozen_amount<amount && (frozen_itr->unfreezes_at) <= cur_time_sec){
        unfrozen_amount += frozen_itr->balance;
        frozen_itr = frozen_cus_idx.erase(frozen_itr);
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
                _item_balance.balance_frozen = _item_balance.balance_frozen - unfrozen_amount;
                _item_balance.balance_in_custody = _item_balance.balance_in_custody + unfrozen_amount;
            });
        }else{
            from_item_balances.modify(item_balances_itr, ram_payer, [&](auto &_item_balance) {
                _item_balance.balance_frozen = _item_balance.balance_frozen - unfrozen_amount;
            });
        }
    }
    return unfrozen_amount;
}
*/
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
zswitems::t_frozen_balances zswitems::get_tbl_frozen_balances(uint64_t custodian_user_pair_id) {
    return zswitems::t_frozen_balances(get_self(), custodian_user_pair_id);
}
zswitems::t_item_tpl_alt_ids zswitems::get_tbl_item_tpl_alt_ids(uint64_t item_template_id) {
    return zswitems::t_item_tpl_alt_ids(get_self(), item_template_id);
}
uint32_t zswitems::require_get_custodian_id_with_permissions(name account, uint128_t permissions) {
    if(account.value == NULL_CUSTODIAN_NAME.value){
        // null can do all so no need to check permissions
        return NULL_CUSTODIAN_ID;
    }
    auto itr = tbl_custodians.get_index<name("byname")>().require_find(account.value, "this user is not a custodian!");


    check(((itr->permissions) & (permissions| CUSTODIAN_PERMS_ENABLED)) == (permissions | CUSTODIAN_PERMS_ENABLED), "this user is missing the required custodian permissions for this action!");
    return itr->custodian_id;

}


uint64_t zswitems::get_custodian_user_pair_id(name ram_payer, name custodian, name user){
    uint128_t user_ind_key =  (((uint128_t)user.value)<<64) | ((uint128_t)custodian.value);
    auto pair_by_user_index = tbl_custodian_user_pairs.get_index<name("byuser")>();
    auto pair_itr = pair_by_user_index.find(user_ind_key);
    if(pair_itr == pair_by_user_index.end()){
        uint64_t next_ind = tbl_custodian_user_pairs.available_primary_key();
        tbl_custodian_user_pairs.emplace(ram_payer, [&](auto &_custodian_user_pair) {
            _custodian_user_pair.custodian_user_pair_id = next_ind;
            _custodian_user_pair.user = user;
            _custodian_user_pair.custodian = custodian;
        });
        return next_ind;
    }else{
        return pair_itr->custodian_user_pair_id;
    }
}