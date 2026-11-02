import importlib

name = "o" + "s"
mod = importlib.import_module(name)
other = __import__(name[::-1])
