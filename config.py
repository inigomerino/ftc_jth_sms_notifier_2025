

# Ensure collections exist and apply indexing
collections = {
    "teams"     : [("team_number"   ,  1, True ), ("name"   ,  1, True )],
    "matches"   : [("matchNumber"   ,  1, True )],
    "admins"    : [("username"      ,  1, True )],
    "api_logs"  : [("timestamp"     , -1, False)]
}

# Define roles and Permissions
roles = {
    "super_admin": [
        "get_teams", "post_teams", "put_teams", "delete_teams",
        "get_matches", "post_matches", "put_matches", "delete_matches",
        "get_admins", "post_admins", "put_admins", "delete_admins",
        "get_api_logs",
        "post_sms",
        # "post_bulk_import", "get_bulk_export"
    ],
    "event_manager": [
        "get_teams", "post_teams", "put_teams", 
        "get_matches", 
        # "post_matches", 
        # "put_matches",
        "post_sms"
    ],
    "messaging_admin": [
        "get_matches",
        "post_sms"
    ],
    "read_only": [
        "get_teams", "get_matches", "get_admins", 
        # "get_bulk_export"
    ]
}