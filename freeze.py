from flask_frozen import Freezer
from nm import app  # Replace with your Flask app's import

freezer = Freezer(app)

if __name__ == '__main__':
    freezer.freeze()