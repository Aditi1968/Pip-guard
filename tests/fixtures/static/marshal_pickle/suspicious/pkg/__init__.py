import marshal
import pickle


def load(blob, code):
    obj = pickle.loads(blob)
    return marshal.loads(code), obj
