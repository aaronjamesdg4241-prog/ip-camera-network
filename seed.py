from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Check if user already exists
    existing_user = User.query.filter_by(username='admin').first()
    if not existing_user:
        hashed_password = generate_password_hash('admin', method='sha256')
        user = User(username='admin', password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print("Admin user created")
    else:
        print("Admin user already exists")
        
