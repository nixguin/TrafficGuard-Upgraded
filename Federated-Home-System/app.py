from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import os

app = Flask(__name__)
CORS(app)

# Secret key for JWT token generation
app.config['SECRET_KEY'] = 'your-secret-key-here'

# In-memory storage for demo purposes (replace with database in production)
users = {
    'admin': 'admin123'
}

routers = []

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users and users[username] == password:
        # Generate JWT token
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'token': token,
            'message': 'Login successful'
        })
    
    return jsonify({
        'message': 'Invalid credentials'
    }), 401

@app.route('/api/routers', methods=['GET'])
def get_routers():
    return jsonify(routers)

@app.route('/api/routers', methods=['POST'])
def add_router():
    data = request.get_json()
    router = {
        'id': len(routers) + 1,
        'name': data.get('name'),
        'ip': data.get('ip'),
        'status': 'active'
    }
    routers.append(router)
    return jsonify(router)

@app.route('/api/routers/<int:router_id>', methods=['PUT'])
def update_router(router_id):
    data = request.get_json()
    for router in routers:
        if router['id'] == router_id:
            router.update(data)
            return jsonify(router)
    return jsonify({'message': 'Router not found'}), 404

@app.route('/api/routers/<int:router_id>', methods=['DELETE'])
def delete_router(router_id):
    for router in routers:
        if router['id'] == router_id:
            routers.remove(router)
            return jsonify({'message': 'Router deleted'})
    return jsonify({'message': 'Router not found'}), 404

@app.route('/api/network-status', methods=['GET'])
def get_network_status():
    return jsonify({
        'status': 'online',
        'connected_devices': len(routers),
        'bandwidth_usage': '45%'
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify([
        {
            'id': 1,
            'type': 'warning',
            'message': 'High bandwidth usage detected',
            'timestamp': datetime.datetime.utcnow().isoformat()
        },
        {
            'id': 2,
            'type': 'info',
            'message': 'New device connected',
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
    ])

if __name__ == '__main__':
    app.run(debug=True, port=5000) 