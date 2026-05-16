from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Check if the user 'pup' already exists
    existing_user = User.query.filter_by(username='pup').first()
    
    if not existing_user:
        # Default secure hashing (scrypt) is used automatically
        hashed_password = generate_password_hash('123')
        user = User(username='pup', password=hashed_password)
        
        db.session.add(user)
        db.session.commit()
        print("User 'pup' created successfully!")
    else:
        print("User 'pup' already exists.")
