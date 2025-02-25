

# externals
import os
import datetime
import re
from bson import ObjectId
import requests
import twilio
import jwt
from flask import Flask, request, session
from flask_restful import Api, Resource
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_session import Session
from pymongo.collection import Collection
from twilio.rest import Client
from dotenv import load_dotenv
from functools import wraps

# Load environment variables from .env file
load_dotenv()

############################## global vars and init ##############################

# Initialize Flask app
app = Flask(__name__)
api = Api(app)

# roles and collections
from config import collections, roles

# Flask
app.config['MONGO_URI'] = os.getenv("MONGO_URI")
app.config['SESSION_TYPE'] = 'filesystem'
app.config['JWT_EXPIRATION_DELTA'] = int(os.getenv("JWT_EXPIRATION_SECONDS", 900))
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "2ManyMonkeysInZKitchen!!")  # Load from environment variables
app.config['SMS_DELIVERY_THRESHOLD'] = float(os.getenv("SMS_DELIVERY_THRESHOLD", 0.33))
app.config['DEBUG'] = os.getenv("DEBUG", "False").lower() == "true"

# Twilio setup
twilio_client = Client(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTH_TOKEN"))
twilio_phone_number = os.getenv("TWILIO_PHONE_NUMBER")

# Initialize extensions
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
Session(app)


############################## helpers ##############################

def ensure_collection_exists(collection_name, indexes=None):
    """
    Check if a collection exists in MongoDB and create it if it does not.
    
    :param db: The MongoDB database object.
    :param collection_name: Name of the collection to check/create.
    :param indexes: List of tuples (field, order, unique) for indexes (optional).
    """
    if collection_name not in mongo.db.list_collection_names():
        mongo.db.create_collection(collection_name)
        print(f"Collection '{collection_name}' created.")

    collection = mongo.db[collection_name]

    # Ensure indexes are created
    if indexes:
        for index_field, order, unique in indexes:
            collection.create_index([(index_field, order)], unique=unique)
            print(f"Index on '{index_field}' created for '{collection_name}' (unique={unique}).")

def flatten_document(doc):
    """
    Converts MongoDB BSON data into a JSON-friendly format.
    - Converts ObjectId to a string
    - Converts datetime to an ISO 8601 string
    """
    doc = dict(doc)  # Convert to a mutable dictionary

    # Convert ObjectId fields
    if "_id" in doc and isinstance(doc["_id"], ObjectId):
        doc["_id"] = str(doc["_id"])  # Convert ObjectId to string

    # Convert timestamp fields
    if "timestamp" in doc and isinstance(doc["timestamp"], datetime.datetime):
        doc["timestamp"] = doc["timestamp"].isoformat()  # Convert datetime to ISO format

    return doc


############################## decorators ##############################

# Authentication decorator
def authenticate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return {"message": "Token is missing"}, 401  # Return dict, not 

        try:
            token = token.split("Bearer ")[-1]  # Handle "Bearer <token>" format
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            request.user = payload  # Attach user data to the request for use in other functions
        except jwt.ExpiredSignatureError as e:
            return {"message": "Token has expired"}, 401
        except jwt.InvalidTokenError as e:
            return {"message": "Invalid token"}, 401

        return f(*args, **kwargs)

    return decorated_function

def require_entitlement(required_entitlements):
    """
    Ensures the user has at least one of the required entitlements.

    :param required_entitlements: A single entitlement (string) or a list of entitlements (list of strings).
    """
    def decorator(f):
        @authenticate  # Ensures authentication before entitlement check
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(request, 'user', {})
            user_entitlements = user.get("entitlements", [])

            # Normalize to a list if a single entitlement is passed
            required_entitlements_list = (
                [required_entitlements] if isinstance(required_entitlements, str) else required_entitlements
            )

            # Check if the user has at least one required entitlement
            if not any(entitlement in user_entitlements for entitlement in required_entitlements_list):
                return {
                    "message": f"Forbidden: Insufficient entitlements. "
                               f"Endpoint requires at least one of the following: {required_entitlements_list}. "
                               f"User has the following: {user_entitlements}"
                }, 403  # Returning a dictionary, not 

            return f(*args, **kwargs)

        return decorated_function

    return decorator

############################## middleware ##############################

# Logging Middleware
@app.after_request
def log_request(response):
    if request.endpoint not in ["static"]:
        log_entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "method": request.method,
            "endpoint": request.path,
            "ip": request.remote_addr,
            "admin": session.get("admin"),
            "json": request.get_json(silent=True),
            "args": request.args.to_dict(),
            "response_status": response.status_code
        }
        mongo.db.api_logs.insert_one(log_entry)
    return response

############################## JWT Authentication ##############################

def generate_jwt_token(user):
    """
    Generates a JWT token for the authenticated user.
    """
    payload = {
        "username": user["username"],
        "role": user.get("role"),
        "entitlements": roles.get(user.get("role"), []),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=app.config['JWT_EXPIRATION_DELTA'])
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')


############################## resources ##############################

class AuthResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"error": "Username and password required"}, 400

        user = mongo.db.admins.find_one({"username": username})
        if not user or not bcrypt.check_password_hash(user["password"], password):
            return {"error": "Invalid username or password"}, 401

        token = generate_jwt_token(user)
        return {"token": token, "role": user.get("role"), "entitlements": roles.get(user.get("role"), [])}

    @authenticate
    def delete(self):
        # return {"message": "Logged out successfully"}
        return {"message": "Logged out successfully"}, 200  # Flask will convert this to JSON automatically

# Base Resource Class
class BaseResource(Resource):

    def __init__(self, collection_name : str):

        # set the var
        self.collection_name = collection_name

        # call parent
        super().__init__()

    def get_collection(self) -> Collection:
        return mongo.db[self.collection_name]    

    def _get_entitlement_name(self, action):
        """Dynamically generate entitlement name using collection_name."""
        return f"{action}_{self.collection_name}"
    
    # protected
    def _get(self, item_id = None):
        """
        Retrieves a list of items with support for search, filtering, sorting, and pagination.
        Uses $regex instead of $text search, but this may cause performance issues on large collections.
        The field to search in is now passed as a query parameter.

        URL Example:
        /your_endpoint?search=John&search_field=name
        """

        # first lets see if they are just asking for one record and handle that first
        # convert to ObjectId
        if item_id is not None:

            try:
                object_id = ObjectId(item_id)  # Convert to ObjectId
            except Exception:
                return {"error": "Invalid ID format"}, 400  # Handle invalid IDs
            
            query_filters = {'_id' : object_id}

            record = self.get_collection().find_one(query_filters)

            # Flatten all documents before sending to the client
            record = flatten_document(record)

            # done
            return record

        else:            

            query_filters = {}

            search_term = request.args.get("search", "").strip()  # Get search term
            search_field = request.args.get("search_field", "name")  # Default to "name"

            if search_term:
                query_filters[search_field] = {"$regex": search_term, "$options": "i"}  # Case-insensitive regex search

            # FIXME: This regex search causes a full collection scan if there's no index on the chosen field
            #        Consider using a text index for better performance.

            page = int(request.args.get("page", 1))
            page_size = int(request.args.get("page_size", 10))
            sort_field = request.args.get("sort", "_id")
            sort_order = int(request.args.get("order", 1))

            total_records = self.get_collection().count_documents(query_filters)
            records = list(self.get_collection()
                        .find(query_filters)
                        .sort(sort_field, sort_order)
                        .skip((page - 1) * page_size)
                        .limit(page_size))
            
            # Flatten all documents before sending to the client
            records = [flatten_document(doc) for doc in records]

            return {"total": total_records, "page": page, "page_size": page_size, "records": records}
    
    def _post(self):
        data = request.get_json()
        if data is None:
            return {"error": "Invalid request"}, 400
        try:
            data = self._perform_data_validation_and_normalization(data)
            self.get_collection().insert_one(data)
            return {"message": "Item added successfully"}
        except Exception as e:
            return {"error": str(e)}, 400

    def _put(self, item_id):
        data = request.get_json()
        if data is None:
            return {"error": "Invalid request"}, 400
        try:
            data = self._perform_data_validation_and_normalization(data)

            # convert to ObjectId
            try:
                object_id = ObjectId(item_id)  # Convert to ObjectId
            except Exception:
                return {"error": "Invalid ID format"}, 400  # Handle invalid IDs

            result = self.get_collection().update_one({"_id": object_id}, {"$set": data})
            if result.matched_count == 0:
                return {"error": "Item not found"}, 404
            return {"message": "Item updated successfully"}
        except Exception as e:
            return {"error": str(e)}, 400

    def _delete(self, item_id):

        # convert to ObjectId
        try:
            object_id = ObjectId(item_id)  # Convert to ObjectId
        except Exception:
            return {"error": "Invalid ID format"}, 400  # Handle invalid IDs

        result = self.get_collection().delete_one({"_id": object_id})
        if result.deleted_count == 0:
            return {"error": "Item not found"}, 404

        return {"message": "Item deleted successfully"}
    
    def _perform_data_validation_and_normalization(self, data):
        return data

    # public methods
    def get(self, item_id=None):
        entitlement_check = require_entitlement(self._get_entitlement_name(request.method.lower()))        
        return entitlement_check(self._get)(item_id)

    # def get(self):
    #     entitlement_check = require_entitlement(self._get_entitlement_name(request.method.lower()))        
    #     return entitlement_check(self._get)()
    
    def post(self):
        entitlement_check = require_entitlement(self._get_entitlement_name(request.method.lower()))
        return entitlement_check(self._post)()

    def put(self, item_id):
        entitlement_check = require_entitlement(self._get_entitlement_name(request.method.lower()))        
        return entitlement_check(self._put)(item_id)

    def delete(self, item_id):
        entitlement_check = require_entitlement(self._get_entitlement_name(request.method.lower()))        
        return entitlement_check(self._delete)(item_id)

# Team Management
class TeamResource(BaseResource):
        
    def __init__(self):
        super().__init__(collection_name="teams")

    def normalize_us_phone_numbers(self, phone_numbers):
        """
        Validates, normalizes, and de-duplicates US phone numbers.

        - Extracts numeric digits, allowing only US numbers.
        - Ensures numbers are exactly 10 digits (or 11 if starting with "1").
        - Converts numbers into international US format: "+1XXXXXXXXXX".
        - Removes duplicates after normalization.

        :param phone_numbers: List of phone numbers in various formats.
        :return: List of unique, normalized US phone numbers.
        """

        normalized_numbers = set()  # Use a set to remove duplicates

        for number in phone_numbers:
            # Remove all non-numeric characters except "+"
            cleaned_number = re.sub(r"[^\d+]", "", number)

            # If the number starts with "+", remove it for easier processing
            if cleaned_number.startswith("+"):
                cleaned_number = cleaned_number[1:]

            # Handle US numbers (must be 10 or 11 digits)
            if len(cleaned_number) == 11 and cleaned_number.startswith("1"):
                # Already includes country code, normalize it
                normalized_number = f"+{cleaned_number}"
            elif len(cleaned_number) == 10:
                # Assume local number, add country code
                normalized_number = f"+1{cleaned_number}"
            else:
                continue  # Reject invalid numbers (not 10 or 11 digits)

            normalized_numbers.add(normalized_number)  # Add to set for uniqueness

        return list(normalized_numbers)  # Convert set back to a list

    def _perform_data_validation_and_normalization(self, data : dict):

        # depends on the method
        if request.method == 'put':
            if 'team_number' in data:
                data['team_number'] = int( data['team_number'] )
            if 'phone_numbers' in data:
                data['phone_numbers'] = self.normalize_us_phone_numbers( data.get('phone_numbers', []) )
            if 'name' in data:
                data['name'] = str( data['name'] )

        if request.method == 'post':
            # required fields
            data['name'] = str( data['name'] )
            data['team_number'] = int( data['team_number'] )
            data['phone_numbers'] = self.normalize_us_phone_numbers( data.get('phone_numbers', []) )

        # done
        return data

# Match Management
class MatchResource(BaseResource):

    def __init__(self):
        super().__init__(collection_name="matches")
    
    def _perform_data_validation_and_normalization(self, data):
        return data
    
    def _post(self):
        """
        Downloads the FTC schedule data from the FIRST API using basic auth
        and imports it into a MongoDB collection with no duplicates.
        """

        ftc_user = os.getenv('FTC_USER')
        ftc_pass = os.getenv('FTC_PASS')
        season = os.getenv('FTC_SEASON')
        event_code = os.getenv('FTC_EVENT_CODE')
        ftc_tournament_level = os.getenv('FTC_TOURNAMENT_LEVEL')
        
        url = f"http://ftc-api.firstinspires.org/v2.0/{season}/schedule/{event_code}"
        params = {'tournamentLevel': ftc_tournament_level}

        try:
            response = requests.get(url, auth=(ftc_user, ftc_pass), params=params)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            return {"error": str(e)}, 400

        # 1. Create a unique index on fields that uniquely identify each match.
        self.get_collection().create_index(
            [
                ("event_code", 1),
                ("tournamentLevel", 1),
                ("matchNumber", 1)
            ], 
            unique=True
        )

        # 2. Extract schedule items from response.
        schedule_items = []
        if isinstance(data, dict):
            schedule_items = data.get('schedule', [])
        elif isinstance(data, list):
            # If the entire JSON is a list, you might want to treat it as schedule items
            schedule_items = data
        else:
            return {"error": "Unexpected data format from API"}, 400

        # 3. Upsert each match. If the match already exists based on the index,
        #    MongoDB will update it instead of inserting a duplicate.
        for item in schedule_items:
            # Add event_code to each document so we can filter on it
            item["event_code"] = event_code

            # Filter based on the unique identifiers
            filter_doc = {
                "tournamentLevel": item["tournamentLevel"],
                "matchNumber": item["matchNumber"],
                "event_code": item["event_code"]
            }

            # Perform an upsert (update if it exists, otherwise insert)
            self.get_collection().update_one(filter_doc, {"$set": item}, upsert=True)

        return {"message": "Data imported or updated successfully."}, 200

# Used to import matches from FTC Events API
class EventResource(BaseResource):

    def __init__(self):
        super().__init__(collection_name="matches")
    

# Admin Management
class AdminResource(BaseResource):

    def __init__(self):
        super().__init__(collection_name="admins")

    def _post(self):
        data = request.get_json()
        if "username" not in data or "password" not in data or "role" not in data:
            return {"error": "Missing required fields"}, 400
        if data["role"] not in roles:
            return {"error": "Invalid role specified."}, 400
        data["password"] = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        try:
            mongo.db.admins.insert_one(data)
            return {"message": "Admin created successfully"}
        except Exception as e:
            return {"error": str(e)}, 400

    def _put(self, item_id):
        data = request.get_json()
        if "role" in data and data["role"] not in roles:
            return {"error": "Invalid role specified."}, 400
        if "password" in data:
            data["password"] = bcrypt.generate_password_hash(data["password"]).decode('utf-8')

        # convert to ObjectId
        try:
            object_id = ObjectId(item_id)  # Convert to ObjectId
        except Exception:
            return {"error": "Invalid ID format"}, 400  # Handle invalid IDs
    
        result = mongo.db.admins.update_one({"_id": object_id}, {"$set": data})
        if result.matched_count == 0:
            return {"error": "Admin not found"}, 404
        return {"message": "Admin updated successfully"}

    def _delete(self, item_id):
        # convert to ObjectId
        try:
            object_id = ObjectId(item_id)  # Convert to ObjectId
        except Exception:
            return {"error": "Invalid ID format"}, 400  # Handle invalid IDs

        result = mongo.db.admins.delete_one({"_id": object_id})
        if result.deleted_count == 0:
            return {"error": "Admin not found"}, 404
        return {"message": "Admin deleted successfully"}

class LogsResource(BaseResource):

    def __init__(self):
        super().__init__(collection_name="api_logs")

# SMS Messaging Resource
class SMSResource(Resource):

    @require_entitlement( ["read_matches", "read_teams", "post_sms", "put_matches"] )
    def post(self, match_id):
        match = mongo.db.matches.find_one({"match_id": match_id})
        if not match:
            return {"error": "Match not found"}, 404

        failed_messages = []
        delivery_threshold = app.config['SMS_DELIVERY_THRESHOLD']
        for team_number in match["red_alliance"] + match["blue_alliance"]:
            team = mongo.db.teams.find_one({"team_number": team_number})
            if not team:
                failed_messages.append({"team_number": team_number, "error": "Team not found"})
                continue

            message_body = f"Match {match_id} is next on Field {match['field_number']}. Your team is in the {'RED' if team_number in match['red_alliance'] else 'BLUE'} alliance. Proceed to your alliance table now."
            successful_sends = 0

            for phone in team["phone_numbers"]:
                if not phone:
                    continue
                try:
                    msg = twilio_client.messages.create(
                        body=message_body,
                        from_=twilio_phone_number,
                        to=phone
                    )
                    if msg.status in ["queued", "sent", "delivered"]:
                        successful_sends += 1
                except twilio.base.exceptions.TwilioRestException as e:
                    failed_messages.append({"team_number": team_number, "phone": phone, "error": str(e)})

            if successful_sends / len(team["phone_numbers"]) < delivery_threshold:
                failed_messages.append({"team_number": team_number, "error": "Message delivery below configured threshold"})

        if failed_messages:
            return {"error": "Some messages failed", "details": failed_messages}, 400

        mongo.db.matches.update_one({"match_id": match_id}, {"$set": {"status": "Notification Sent", "last_notification_time": datetime.datetime.now(datetime.timezone.utc)}})
        return {"message": "Notifications sent successfully"}

# Registering API resources
api.add_resource(AuthResource,  '/api/v1/auth',     '/api/v1/auth/<string:item_id>')
api.add_resource(TeamResource,  '/api/v1/teams',    '/api/v1/teams/<string:item_id>')
api.add_resource(MatchResource, '/api/v1/matches',  '/api/v1/matches/<string:item_id>')
api.add_resource(AdminResource, '/api/v1/admins',   '/api/v1/admins/<string:item_id>')
api.add_resource(LogsResource,  '/api/v1/api_logs', '/api/v1/api_logs/<string:item_id>')
api.add_resource(SMSResource,   '/api/v1/matches/<int:match_id>/notify')
api.add_resource(EventResource, '/api/v1/matches/import_schedule')


if __name__ == "__main__":

    if not app.config['DEBUG']:
        print("Running in production mode: Debug mode is disabled.")

    # ensure collections exist
    for collection_name, indexes in collections.items():
        ensure_collection_exists(collection_name, indexes)

    app.run(debug=app.config['DEBUG'], port=5100)
