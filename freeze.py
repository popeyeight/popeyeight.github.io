from flask_frozen import Freezer
from app import app  # Replace with your Flask app's import

freezer = Freezer(app)

if __name__ == '__main__':
    try:
        freezer.freeze()
        print("Freezing successful.")
    except Exception as e:
        print(f"Error during freezing: {e}")
