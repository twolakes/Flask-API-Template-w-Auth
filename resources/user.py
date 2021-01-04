import sqlite3
from flask_restful import Resource, reqparse
from flask_jwt_extended import(
    create_access_token, create_refresh_token, jwt_required,
    jwt_refresh_token_required, get_jwt_identity, get_jwt_claims, get_raw_jwt)

from security import(
    encrypt_password, check_encrypted_password)
from models.user import UserModel
from blacklist import BLACKLIST

_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username',
    type = str,
    required=True,
    help="This field cannot be left blank"
)
_user_parser.add_argument('password',
    type = str,
    required=True,
    help="This field cannot be left blank"
)


class UserRegister(Resource):
    
    def post(self):
        data = _user_parser.parse_args()
        data.password = encrypt_password(data.password)

        if UserModel.find_by_username(data['username']):
            return {"message": f"User {username} already exists."}, 400

        user = UserModel(**data)
        user.save_to_db()

        return {"message": "User created successfully."}, 201


class UserLogin(Resource):

    def post(self):

        data = _user_parser.parse_args()
        user = UserModel.find_by_username(data['username'])
        if user and check_encrypted_password(data['password'], user.password):
            access_token = create_access_token(identity=user, fresh=True)
            refresh_token = create_refresh_token(user)
            return {
                "access_token": access_token,
                "refresh_token": refresh_token
            }, 200
        
        return {"message": "invalid credentials"}, 401


class UserLogout(Resource):

    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        return {"message": "Successfully logged out"}


class User(Resource):

    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": "user not found"}, 404
        
        return user.json()

    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": "User not found"}, 404
        
        user.delete_from_db()
        return {"message": "User deleted"}, 200


class UserList(Resource):

    @jwt_required
    def get(self):
        # return {"users": [user.json() for user in UserModel.find_all()]}
        ret = {
            'current_identity': get_jwt_identity(),
            'current_claims': get_jwt_claims()['username']
        }

        return {"data": ret}, 200


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = UserModel.find_by_id(get_jwt_identity())
        new_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token": new_token}, 200