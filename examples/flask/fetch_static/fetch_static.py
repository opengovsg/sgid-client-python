import requests, zipfile
from io import BytesIO
import os

SOURCE_FILENAME = "dist.zip"
SOURCE_URL = "https://d2m9b44i9bvctd.cloudfront.net/" + SOURCE_FILENAME


def fetch_static_files():
    if os.path.isdir("static"):
        print("static directory already exists, no need to download static files.")
        return
    print("Fetching static files...")
    r = requests.get(SOURCE_URL)
    zipped = zipfile.ZipFile(BytesIO(r.content))
    zipped.extractall(".")
    # Rename static folder to match Flask default
    os.rename("dist", "static")
