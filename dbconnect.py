import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId
import config



def connection():
    uri = "mongodb://" + config.mongodb_username + ":" + config.mongodb_password + "@" + config.mongodb_host + ":" + config.mongodb_port + "/" + config.mongodb_db
    client = MongoClient(uri)
    db = client.moitdashboard
    return client, db

if __name__ == "__main__":
    client, db = connection()
    print(client)