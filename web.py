from flask import Flask, request, jsonify

app = Flask(__name__)
TOKENS = {"token-alice": "alice", "token-bob": "bob"}
ORDERS = {
    1: {"owner": "alice", "item": "Laptop", "address": "12 Nile St, Alexandria"},
    2: {"owner": "bob",   "item": "Phone",  "address": "7 Corniche Rd, Cairo"},
}

def current_user():
    return TOKENS.get(request.headers.get("Authorization", "").replace("Bearer ", ""))

@app.route("/")
def index():
    return '<a href="/api/orders/1">orders</a> <a href="/api/safe/orders/1">safe orders</a>'

# VULNERABLE: checks you're logged in, never checks you own the order
@app.route("/api/orders/<int:oid>")
def get_order(oid):
    if not current_user():
        return jsonify(error="unauthorized"), 401
    o = ORDERS.get(oid)
    return (jsonify(o), 200) if o else (jsonify(error="not found"), 404)

# SAFE (control): checks ownership
@app.route("/api/safe/orders/<int:oid>")
def get_order_safe(oid):
    user = current_user()
    if not user:
        return jsonify(error="unauthorized"), 401
    o = ORDERS.get(oid)
    if not o or o["owner"] != user:
        return jsonify(error="forbidden"), 403
    return jsonify(o)

app.run(port=5000)