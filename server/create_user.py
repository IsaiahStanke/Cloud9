from server import db, User, app  # Assuming your main script is server.py

# Ensure that you are working within the Flask application context
with app.app_context():
    # Ensure the database is created (if not already created)
    db.create_all()

    # Create a new user
    username = "admin"
    password = "admin_password"

    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"User {username} already exists.")
    else:
        # Create new user
        user = User(username=username)
        user.set_password(password)  # Securely set the password
        db.session.add(user)
        db.session.commit()
        print(f"User {username} has been created.")
