from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Check if user already exists
    existing_user = User.query.filter_by(username='admin').first()
    if not existing_user:
        # Removed deprecated 'method' arg to allow default scrypt hashing
        hashed_password = generate_password_hash('admin')
        user = User(username='admin', password=hashed_password)
        db.session.add(user)
        db.session.commit()
        print("Admin user created successfully.")
    else:
        print("Admin user already exists.")
