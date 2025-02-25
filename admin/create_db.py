import os
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv()

# Connect to MongoDB (Make sure MongoDB is running)
client = MongoClient(os.getenv('MONGO_SRV'))

# Create or connect to the database
db_name = os.getenv('MONGO_DB')
db = client[ db_name ]

# Define the collection name
collection_name = "test_collection"

# Create or connect to the collection
collection = db[collection_name]

# Insert a test document
test_document = {"name": "John Doe", "age": 30, "city": "New York"}
insert_result = collection.insert_one(test_document)

# Print success message
print(f"Database '{db_name}' and collection '{collection_name}' created successfully!")
print(f"Inserted document ID: {insert_result.inserted_id}")

# Verify by fetching one document
retrieved_doc = collection.find_one()
doc_id = retrieved_doc['_id']
print("Retrieved document:", retrieved_doc)

# Clean up recxord
r = collection.delete_one({'_id' : doc_id} )
print(f"Deleted document id {doc_id}: {r}")

# Drop test collection
db[collection_name].drop()
print(f"Deleted collection {collection_name}")

# Close the connection
client.close()