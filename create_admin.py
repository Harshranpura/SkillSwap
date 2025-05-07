from pymongo import MongoClient
from bson import ObjectId
import os
from dotenv import load_dotenv

# Load environment variables (if using .env file)
load_dotenv()

# Connect to your MongoDB - use the same connection string as your main app
mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/SkillSwap")
client = MongoClient(mongo_uri)
db = client['SkillSwap']
users = db['Users']

# First list all users so you can choose which one to make admin
print("Available users:")
for user in users.find():
    print(f"ID: {user['_id']}, Name: {user.get('full_name', 'N/A')}, Email: {user.get('email', 'N/A')}")

# Get user ID input
user_id = input("\nEnter the ID of the user to make admin: ")

# Update user to superadmin
try:
    result = users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'role': 'superadmin'}}
    )
    
    if result.matched_count == 1:
        print(f"Success! User with ID {user_id} has been upgraded to superadmin role.")
    else:
        print(f"Error: No user found with ID {user_id}")
        
except Exception as e:
    print(f"Error updating user: {e}")

print("\nDone!")