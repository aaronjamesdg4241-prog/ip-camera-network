from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Force creation/validation of tables specifically within the seed context
    db.create_all()
    
    # Target our desired user
    existing_user = User.query.filter_by(username='pup').first()
    
    if not existing_user:
        hashed_password = generate_password_hash('123')
        user = User(username='pup', password=hashed_password)
        
        try:
            db.session.add(user)
            db.session.commit()
            print("User 'pup' created successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"Database insertion failed: {e}")
    else:
        print("User 'pup' already exists.")
