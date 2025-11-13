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

REGION = os.environ.get("REGION")
BUCKET = os.environ.get("BUCKET")

app.secret_key = os.environ.get("SECRET_ACCESS_KEY")  # needed for session
s3 = boto3.client("s3", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(os.environ.get("TABLE"))
db = mysql.connector.connect(
    host=os.environ.get("HOST"),
    user=os.environ.get("DBUSER"),
    password=os.environ.get("PASSWORD"),
    database=os.environ.get("DATABASE")
)

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
    try:
        user = query(db, "SELECT * FROM students WHERE name = %s", (name,), True)[0]
    except IndexError:
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
        # if 'file' not in request.files:
            # return jsonify({'error': 'No file uploaded'}), 400
    
        file = request.files['image']
        title = request.form.get('title')
        description = request.form.get('description')
        user_id = session.get("user_id", None)

        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        unique_id = str(uuid.uuid4())
        filename = f"{unique_id}_{file.filename}"

        try:
            # Get file size before upload
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)  # reset pointer to start for upload

            # Upload file to S3
            s3.upload_fileobj(
                file,
                BUCKET,
                filename,
                ExtraArgs={'ContentType': file.content_type}
            )

            # Prepare metadata
            file_url = f"https://{BUCKET}.s3.{REGION}.amazonaws.com/{filename}"
            mime_type = file.content_type
            now = datetime.utcnow().isoformat() + "Z"

            # Insert metadata into DynamoDB
            table.put_item(Item={
                "id": unique_id,
                "user_id": user_id,
                "title": title,
                "description": description,
                "filename": filename,
                "url": file_url,
                "mime_type": mime_type,
                "size": size,
                "uploaded_at": now,
                "last_edited_at": now
            })

            return jsonify({
                'message': 'File uploaded successfully',
                'file_url': file_url
            }), 200
        
        except Exception as e:
            raise e

    return id

@app.route("/files")
def files():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    user_id = session["user_id"]
    response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr("user_id").eq(user_id)
        )
    items = response.get("Items", [])

    return jsonify(items)

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/login")


if __name__ == '__main__':
    app.run("0.0.0.0", port=os.environ["PORT"], debug=True)