from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_cors import CORS #so that different IP's can reach out to our site/ doesn't block other IP's 
from bson.objectid import ObjectId
import bcrypt
import jwt

app = Flask(__name__)
CORS(app,    resources = {r"/*":{"origins":"*"}})
#CORS(app,  resources = {r"/*": { "origins": "https:localhost:3000" }}) you can select a specific IP 

#connect to mongodb
# strconnect = "mongodb://yasminne:Aa123456@cluster0.lmebt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
try:
    client = MongoClient("mongodb+srv://yasminne:Aa123456@cluster0.lmebt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    print("Connection Successful")
except Exception as e:
    print("Errorzz:", e)

db = client['mydb']  # DB name in mongoDB
users_collection = db['users'] #collection is a table in the db in mongoDB

#secret key for JWT
SECRET_KEY = 'your_jwt_secret_key_here'
#helper function to generate JWT token
def generate_jwt(user_id):
    payload = {
        'user_id':str(user_id),
        'exp':60*60*24 # one day
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    firstname = data.get("firstname")
    lastname = data.get("lastname")
    email = data.get("email")
    password = data.get("password")
    if not firstname or not lastname or not email or not password:
        return jsonify({"error": "missing fields"}), 400
    
    #check user
    if users_collection.find_one({"email": email}):  #find_one is mongodb function
        return jsonify({"error": "email already exists"})
    
    #hased password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    #create new user
    user = {
        "firstname": firstname, 
        "lastname": lastname,
        "email": email,
        "password": hashed_password
    }

    user_id = users_collection.insert_one(user).inserted_id  #returns the id of the user i created 
    print(user)
    return jsonify({
        "message": "users registered successfully!",
        "user_id": str(user_id),
    }), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"error":"Missing fields"}), 400 
    
    #find the user in db 
    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error":"invalid cradentials"}), 401 
    print(user)

    #check password 
    if not bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        return jsonify({"error":"invalid cradentials"}), 401 
    
    token = generate_jwt(user['_id'])
    return jsonify({
        "message":"Login successfully",
        "token":token,
    }), 200 


@app.route('/users', methods=['GET'])
def get_all_users():
    token = request.headers.get('Authorization')  #token is in the headers in Authorization part 
    if not token: 
        return jsonify({"error": "Token is missing"})
    #split the Bearer part from the actual token
    try:
        token_type, token_value = token.split(" ")  #a b => ["Bearer", "token-ekaajhagjhlawfh"]
        print("------------------")
        print(token_type, token_value)
        # decode_token = jwt.decode(token_value, SECRET_KEY, algorithms=['HS256'])
        # print(decode_token)
        if token_type.lower() != "bearer":
            return jsonify({"error": "invalid token type"})
    except ValueError:
        return jsonify({"error": "invalid token format"})

    #fetch all users from mongodb
    users = list(users_collection.find({}, {"_id": 1, "firstname":1, "lastname": 1, "email": 1})) 
    # 1 means True/ the first{} are the conditions, for example i want {firstname="hagar"}
    for user in users:
        user['_id'] = str(user['_id']) #id stored as an object in mongodb so you have to convert it to string
    return jsonify(users), 200


@app.route("/users/<id>", methods=["GET"])
def get_one_user(id):
    user = users_collection.find_one({"_id":ObjectId(id)}, {"_id":1, "firstname":1, "lastname":1, "email":1})
    if user:
        user['_id'] = str(user['_id'])
        return jsonify(user), 200 
    else:
        return jsonify({"error", "User not found"})

@app.route("/users/<id>" , methods=['DELETE'])
def delete_user(id):
    result = users_collection.delete_one({"_id":ObjectId(id)})
    if result.deleted_count == 0:
        return jsonify({"error":"User not found"}), 404 
    return jsonify({"message":"User deleted"}), 200 

@app.route("/users/<id>", methods=['PATCH'])
def update_user(id):
    data = request.get_json()

    updated_fields= {k:v for k, v in data.items() if k in ['firstname', 'lastname', 'email', 'password']}
    if not updated_fields:
        return jsonify({"error":"No fields to update"})
    
    result = users_collection.update_one({"_id": ObjectId(id)}, {"$set": updated_fields})
    if result.matched_count == 0:
        return jsonify({"error", "User not found"}), 404 
    
    user = users_collection.find_one({"_id":ObjectId(id)}, {"_id":1, "firstname":1, "lastname":1, "email":1})
    #user = users_collection.find_one_and_update({"_id":ObjectId(id)},{"$set": updated_fields}, return_document=True)
    if user:
        user['_id'] = str(user['_id'])
    return jsonify(user), 200 

if __name__ == "__main__":
    app.run(debug= True)