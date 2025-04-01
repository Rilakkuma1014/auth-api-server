from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
auth = HTTPBasicAuth()
users = {}

@auth.verify_password
def verify_password(username, password):
    user = users.get(username)
    if user and check_password_hash(user['password'], password):
        return username
    return None

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    user_id = data.get('user_id')
    password = data.get('password')

    if not user_id or not password:
        return jsonify({"message": "Account creation failed", "cause": "Required user_id and password"}), 400
    if not (6 <= len(user_id) <= 20 and 8 <= len(password) <= 20):
        return jsonify({"message": "Account creation failed", "cause": "Input length is incorrect"}), 400
    if not re.fullmatch(r'[a-zA-Z0-9]+', user_id) or not re.fullmatch(r'[a-zA-Z0-9!-/:-@¥[-`{-~]+', password):
        return jsonify({"message": "Account creation failed", "cause": "Incorrect character pattern"}), 400
    if user_id in users:
        return jsonify({"message": "Account creation failed", "cause": "Already same user_id is used"}), 400

    users[user_id] = {
        "password": generate_password_hash(password),
        "nickname": user_id,
        "comment": ""
    }
    return jsonify({"message": "Account successfully created", "user": {"user_id": user_id, "nickname": user_id}}), 200

@app.route('/users/<user_id>', methods=['GET'])
@auth.login_required
def get_user(user_id):
    if auth.current_user() != user_id:
        return jsonify({"message": "Authentication failed"}), 401
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404

    user = users[user_id]
    return jsonify({"message": "User details by user_id", "user": {
        "user_id": user_id,
        "nickname": user.get("nickname", user_id),
        "comment": user.get("comment", "")
    }}), 200

@app.route('/users/<user_id>', methods=['PATCH'])
@auth.login_required
def patch_user(user_id):
    if auth.current_user() != user_id:
        return jsonify({"message": "No permission for update"}), 403
    if user_id not in users:
        return jsonify({"message": "No user found"}), 404

    data = request.json
    nickname = data.get('nickname')
    comment = data.get('comment')

    if nickname is None and comment is None:
        return jsonify({"message": "User updation failed", "cause": "Required nickname or comment"}), 400

    if nickname is not None:
        if len(nickname) > 30 or re.search(r'[\x00-\x1F\x7F]', nickname):
            return jsonify({"message": "User updation failed", "cause": "Invalid nickname or comment"}), 400
        users[user_id]['nickname'] = nickname if nickname != "" else user_id

    if comment is not None:
        if len(comment) > 100 or re.search(r'[\x00-\x1F\x7F]', comment):
            return jsonify({"message": "User updation failed", "cause": "Invalid nickname or comment"}), 400
        users[user_id]['comment'] = comment

    return jsonify({"message": "User successfully updated", "user": {
        "nickname": users[user_id]['nickname'],
        "comment": users[user_id]['comment']
    }}), 200

@app.route('/close', methods=['POST'])
@auth.login_required
def close_account():
    user_id = auth.current_user()
    if user_id in users:
        del users[user_id]
    return jsonify({"message": "Account and user successfully removed"}), 200
