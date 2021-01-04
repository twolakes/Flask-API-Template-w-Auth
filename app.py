from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.user import UserRegister, UserLogin, User, UserList, TokenRefresh, UserLogout
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from blacklist import BLACKLIST

from db import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# jwt extended blacklist (see loader below)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

app.config['JWT_SECRET_KEY'] = 'super-secret'   # <<<<<< MOVE TO ENV VARS
app.secret_key = 'My Secret Key'                # <<<<<< MOVE TO ENV VARS
api = Api(app)

@app.before_first_request
def create_tables():
    db.create_all()

jwt = JWTManager(app)

@jwt.user_claims_loader
def add_claims_to_jwt(user):
    return {'username': user.username}

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token['jti'] in BLACKLIST
    # if true, will move on to revoked token loader
    # which will return error

@jwt.revoked_token_loader
def revoked_token_callback():
    return jsonify({
        "description": "The token is revoked",
        "error": "token_revoked"
    }), 401

@jwt.expired_token_loader   #override default message
def expired_token_callback():
    return jsonify({
        "description": "The token has expired",
        "error": "token_expired"
    }), 401


@app.route('/')
def get():
    return "OK"


api.add_resource(Store, '/store/<string:name>')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(StoreList, '/stores')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserList, '/users')
api.add_resource(TokenRefresh, '/refresh')

if __name__ == '__main__':
    db.init_app(app)
    app.run(port=5000, debug=True)

