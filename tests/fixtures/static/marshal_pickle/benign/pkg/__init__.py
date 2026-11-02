import json
import pickle


def save(obj):
    return pickle.dumps(obj), json.loads("{}")
