import os
import boto3
import mysql.connector
import bcrypt
import uuid

from datetime import datetime
from flask import Flask, jsonify, redirect, url_for, request, session
from dotenv import load_dotenv
from utils import query

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_ACCESS_KEY")  # needed for session
s3 = boto3.client("s3", region_name=os.environ.get("REGION"))
dynamo = boto3.client("dynamodb", region_name=os.environ.get("REGION"))
db = mysql.connector.connect(
    host=os.environ.get("HOST"),
    user=os.environ.get("DBUSER"),
    password=os.environ.get("PASSWORD"),
    database=os.environ.get("DATABASE")
)

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

#If windows, use this:
if os.name == "nt":
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.environ.get("ACCESS_KEY"),
        aws_secret_access_key=os.environ.get("SECRET_ACCESS_KEY"),
        region_name=os.environ.get("REGION"),
    )

    dynamo = boto3.client(
        'dynamodb',
        aws_access_key_id=os.environ.get("ACCESS_KEY"),
        aws_secret_access_key=os.environ.get("SECRET_ACCESS_KEY"),
        region_name=os.environ.get("REGION"),
    )

@app.route('/students', defaults={'id': None}, methods=["POST"])
@app.route('/students/<id>', methods=["GET", "DELETE", "PUT"])
def users(id: int):
    if request.method == "POST":
        data = request.get_json()  # Parses JSON automatically
        query(
            db, 
            "INSERT INTO students (name, password, class, major) VALUES (%s, %s, %s, %s)",
            (data['name'], bcrypt.hashpw(data['password'].encode("utf-8"), bcrypt.gensalt()), data['class'], data['major'])
        )
        return jsonify(success=True)
    
    elif request.method == "GET":
        data = query(
            db, 
            "SELECT * FROM students WHERE id = %s",
            (id,),
            True
        )

        if not data:
            return jsonify(success=False)
        
        return data[0]
    return "Hello World"

#curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"name\": \"R\", \"password\": \"skaskaps\"}

@app.route('/login', methods=["POST"])
def login():
    data = request.get_json()
    name = data.get("name")
    password = data.get("password")
    user = query(db, "SELECT * FROM students WHERE name = %s", (name,), True)[0]
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
        session["username"] = user["name"]
        session["user_id"] = user["id"]
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid password"}), 401


@app.route("/session")
def get_session():
    if "user_id" in session:
        return jsonify({"logged_in": True, "username": session["username"]})
    else:
        return jsonify({"logged_in": False})
    
@app.route('/upload', methods=["GET", "POST", "PUT"])
def upload():
    if request.method == "POST":
        file = request.files["image"]
        title = request.form["title"]
        description = request.form["description"]

        if not file:
            return "No file selected!", 400

        ext = os.path.splitext(file.filename)[1]
        filename = f"{uuid.uuid4()}{ext}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        url = url_for("static", filename=f"uploads/{filename}")
        mime_type = file.mimetype
        size = os.path.getsize(file_path)
        now = datetime.now().isoformat()
        user_id = session.get("user_id", None)

        query(db, "INSERT INTO images (user_id, title, description, filename, url, mime_type, size, uploaded_at, last_edited_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", (user_id, title, description, filename, url, mime_type, size, now, now))

        return jsonify({
            "message": "Upload successful",
            "file": {
                "filename": filename,
                "url": url
            }
        }), 201
        
    return id

@app.route("/files")
def files():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    user_id = session["user_id"]
    files = query(db, """
        SELECT id, title, description, filename, url, mime_type, size, uploaded_at, last_edited_at
        FROM images
        WHERE user_id = %s
        ORDER BY uploaded_at DESC
    """, (user_id,), True)
    return jsonify(files)

#{
#   "id": ...,
#   "name": ...,
#   "class": ...,
#   "major": ....
#}

# {
#   "id": 1,
#   "user_id": 42,
#   "title": "Homework 3 - Geometry",
#   "description": "My diagram for triangle problem",
#   "filename": "triangle_homework.png",
#   "url": "S3_URL"
#   "mime_type": "image/png",
#   "size": 245600,
#   "uploaded_at": "2025-11-07T14:32:00Z",
#   "last_edited_at": "2025-11-07T14:32:00Z"
# }


if __name__ == '__main__':
    app.run("0.0.0.0", port=os.environ["PORT"], debug=True)