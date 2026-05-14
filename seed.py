from app import app, db, User

with app.app_context():
    user = User(username='admin', password='admin')
    db.session.add(user)
    db.session.commit()
    print("Admin user created")
