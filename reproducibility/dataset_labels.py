import re

def app_package(filename):
    return re.split(r"_\d{4}-\d{2}-\d{2}-",filename,maxsplit=1)[0]
