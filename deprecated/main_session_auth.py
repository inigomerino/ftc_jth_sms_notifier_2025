

# externals
import os
import datetime
import twilio
from flask import Flask, jsonify, request, session
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

# Initialize Flask app
app = Flask(__name__)
api = Api(app)

# Initialize extensions
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
Session(app)

############################## global vars and init ##############################

# roles and collections
from config import collections, roles

# Flask
app.config['MONGO_URI'] = os.getenv("MONGO_URI")
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv("SESSION_TIMEOUT_SECONDS", 900))
app.config['SMS_DELIVERY_THRESHOLD'] = float(os.getenv("SMS_DELIVERY_THRESHOLD", 0.33))
app.config['DEBUG'] = os.getenv("DEBUG", "False").lower() == "true"

# Twilio setup
twilio_client = Client(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTH_TOKEN"))
twilio_phone_number = os.getenv("TWILIO_PHONE_NUMBER")

############################## helpers ##############################

def ensure_collection_exists(db, collection_name, indexes=None):
    """
    Check if a collection exists in MongoDB and create it if it does not.
    
    :param db: The MongoDB database object.
    :param collection_name: Name of the collection to check/create.
    :param indexes: List of tuples (field, order, unique) for indexes (optional).
    """
    if collection_name not in db.list_collection_names():
        db.create_collection(collection_name)
        print(f"Collection '{collection_name}' created.")

    collection = db[collection_name]

    # Ensure indexes are created
    if indexes:
        for index_field, order, unique in indexes:
            collection.create_index([(index_field, order)], unique=unique)
            print(f"Index on '{index_field}' created for '{collection_name}' (unique={unique}).")


############################## decorators ##############################

# Authentication decorator
def authenticate(f):
    def wrapper(*args, **kwargs):
        if 'admin' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

def require_entitlement(required_entitlement):
    """
    Decorator to restrict access based on user entitlements.
    :param required_entitlement: String representing the required entitlement (e.g., "post_sms").
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'admin' not in session:
                return jsonify({"error": "Unauthorized: No active session"}), 401
            
            user_entitlements = session.get("entitlements", [])
            if required_entitlement not in user_entitlements:
                return jsonify({"error": f"Forbidden: Insufficient privileges (missing entitlement '{required_entitlement}')"}), 403
            
            return f(*args, **kwargs)
        return wrapper
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


############################## resources ##############################

class AuthResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        user = mongo.db.admins.find_one({"username": username})
        if not user or not bcrypt.check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid username or password"}), 401

        session["admin"] = username
        session["role"] = user.get("role")
        session["entitlements"] = roles.get(user["role"], [])
        session.permanent = True  # Apply session timeout

        return jsonify({"message": "Login successful", "role": session["role"], "entitlements": session["entitlements"]})

    @authenticate
    def delete(self):
        session.clear()
        return jsonify({"message": "Logged out successfully"})

# Base Resource Class
class BaseResource(Resource):
    collection_name = None

    def get_collection(self) -> Collection:
        return mongo.db[self.collection_name]

    @authenticate
    @require_entitlement(f"get_{collection_name}")
    def get(self):
        """
        Retrieves a list of items with support for search, filtering, sorting, and pagination.
        """
        query_filters = {}
        if 'search' in request.args:
            query_filters['$text'] = {'$search': request.args['search']}
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 10))
        sort_field = request.args.get("sort", "_id")
        sort_order = int(request.args.get("order", 1))
        total_records = self.get_collection().count_documents(query_filters)
        records = list(self.get_collection().find(query_filters).sort(sort_field, sort_order).skip((page - 1) * page_size).limit(page_size))
        return jsonify({"total": total_records, "page": page, "page_size": page_size, "records": records})

    @authenticate
    @require_entitlement(f"post_{collection_name}")
    def post(self):
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        try:
            self.get_collection().insert_one(data)
            return jsonify({"message": "Item added successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @authenticate
    @require_entitlement(f"put_{collection_name}")
    def put(self, item_id):
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        result = self.get_collection().update_one({"_id": item_id}, {"$set": data})
        if result.matched_count == 0:
            return jsonify({"error": "Item not found"}), 404
        return jsonify({"message": "Item updated successfully"})

    @authenticate
    @require_entitlement(f"delete_{collection_name}")
    def delete(self, item_id):
        result = self.get_collection().delete_one({"_id": item_id})
        if result.deleted_count == 0:
            return jsonify({"error": "Item not found"}), 404
        return jsonify({"message": "Item deleted successfully"})

# Team Management
class TeamResource(BaseResource):
    collection_name = "teams"

# Match Management
class MatchResource(BaseResource):
    collection_name = "matches"

# Admin Management
class AdminResource(BaseResource):
    collection_name = "admins"

    @authenticate
    @require_entitlement(f"post_{collection_name}")
    def post(self):
        if "manage_admins" not in roles.get(session.get("role"), []):
            return jsonify({"error": "Unauthorized: You do not have permission to create admins."}), 403
        data = request.get_json()
        if "username" not in data or "password" not in data or "role" not in data:
            return jsonify({"error": "Missing required fields"}), 400
        if data["role"] not in roles:
            return jsonify({"error": "Invalid role specified."}), 400
        data["password"] = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        try:
            mongo.db.admins.insert_one(data)
            return jsonify({"message": "Admin created successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @authenticate
    @require_entitlement(f"put_{collection_name}")
    def put(self, item_id):
        if "manage_admins" not in roles.get(session.get("role"), []):
            return jsonify({"error": "Unauthorized: You do not have permission to modify admins."}), 403
        data = request.get_json()
        if "role" in data and data["role"] not in roles:
            return jsonify({"error": "Invalid role specified."}), 400
        if "password" in data:
            data["password"] = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        result = mongo.db.admins.update_one({"_id": item_id}, {"$set": data})
        if result.matched_count == 0:
            return jsonify({"error": "Admin not found"}), 404
        return jsonify({"message": "Admin updated successfully"})

    @authenticate
    @require_entitlement(f"delete_{collection_name}")
    def delete(self, item_id):
        if "manage_admins" not in roles.get(session.get("role"), []):
            return jsonify({"error": "Unauthorized"}), 403
        result = mongo.db.admins.delete_one({"_id": item_id})
        if result.deleted_count == 0:
            return jsonify({"error": "Admin not found"}), 404
        return jsonify({"message": "Admin deleted successfully"})

class LogsResource(BaseResource):
    collection_name = "api_logs"

    @authenticate
    @require_entitlement(f"get_{collection_name}")
    def get(self):
        if "delete_logs" not in roles.get(session.get("role"), []):
            return jsonify({"error": "Unauthorized: You do not have permission to access logs."}), 403
        query_filters = {}
        if 'search' in request.args:
            query_filters['$text'] = {'$search': request.args['search']}
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 10))
        total_records = self.get_collection().count_documents(query_filters)
        records = list(self.get_collection().find(query_filters).skip((page - 1) * page_size).limit(page_size))
        return jsonify({"total": total_records, "page": page, "page_size": page_size, "records": records})

    @authenticate
    @require_entitlement(f"get_{collection_name}")
    def get(self):
        if "delete_logs" not in roles.get(session.get("role"), []):
            return jsonify({"error": "Unauthorized"}), 403
        return super().get()

# SMS Messaging Resource
class SMSResource(Resource):

    @authenticate
    @require_entitlement(f"read_matches")
    @require_entitlement(f"read_teams")
    @require_entitlement(f"post_sms")
    @require_entitlement(f"put_matches")
    def post(self, match_id):
        match = mongo.db.matches.find_one({"match_id": match_id})
        if not match:
            return jsonify({"error": "Match not found"}), 404

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
            return jsonify({"error": "Some messages failed", "details": failed_messages}), 400

        mongo.db.matches.update_one({"match_id": match_id}, {"$set": {"status": "Notification Sent", "last_notification_time": datetime.datetime.now(datetime.timezone.utc)}})
        return jsonify({"message": "Notifications sent successfully"})

# Registering API resources
api.add_resource(TeamResource,  '/api/v1/teams',    '/api/v1/teams/<string:item_id>')
api.add_resource(MatchResource, '/api/v1/matches',  '/api/v1/matches/<string:item_id>')
api.add_resource(AdminResource, '/api/v1/admins',   '/api/v1/admins/<string:item_id>')
api.add_resource(LogsResource,  '/api/v1/logs',     '/api/v1/logs/<string:item_id>')
api.add_resource(SMSResource,   '/api/v1/matches/<int:match_id>/notify')

if __name__ == "__main__":

    if not app.config['DEBUG']:
        print("Running in production mode: Debug mode is disabled.")

    # ensure collections exist
    for collection_name, indexes in collections.items():
        ensure_collection_exists(collection_name, indexes)

    app.run(debug=app.config['DEBUG'])
    app.run(debug=app.config['DEBUG'])
