from flask import Flask , jsonify , request
from flask_sqlalchemy import SQLAlchemy
import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required,get_jwt_identity, unset_jwt_cookies

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
db = SQLAlchemy(app)
jwt = JWTManager(app) 

# Define  SQLAlchemy models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)  
    password = db.Column(db.String(100), nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(50), nullable=False)
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
#user register
@app.route("/register" , methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    password_hash = generate_password_hash(password)
    new_user = User(username=username,password=password_hash)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201
#login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid username or password'}), 401
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    resp = jsonify({'message': 'Logged out successfully'})
    unset_jwt_cookies(resp)
    return resp, 200
# Define CRUD Routes for Posts
@app.route('/posts', methods=['GET'])
def get_posts():
    posts = Post.query.all()
    return jsonify([{'id': post.id, 'title': post.title, 'content': post.content} for post in posts])

@app.route('/posts', methods=['POST'])
def create_post():
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    if title and content:
        new_post = Post(title=title, content=content)
        db.session.add(new_post)
        db.session.commit()
        return jsonify({'message': 'Post created successfully'}), 201
    else:
        return jsonify({'error': 'Missing title or content'}), 400

@app.route('/posts/<int:id>', methods=['GET'])
def get_post(id):
    post = Post.query.get(id)
    if post:
        return jsonify({'id': post.id, 'title': post.title, 'content': post.content})
    else:
        return jsonify({'error': 'Post not found'}), 404

@app.route('/posts/<int:id>', methods=['PUT'])
def update_post(id):
    post = Post.query.get(id)
    if post:
        data = request.get_json()
        title = data.get('title')
        content = data.get('content')
        if title and content:
            post.title = title
            post.content = content
            db.session.commit()
            return jsonify({'message': 'Post updated successfully'}), 200
        else:
            return jsonify({'error': 'Missing title or content'}), 400
    else:
        return jsonify({'error': 'Post not found'}), 404

@app.route('/posts/<int:id>', methods=['DELETE'])
def delete_post(id):
    post = Post.query.get(id)
    if post:
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted successfully'}), 200
    else:
        return jsonify({'error': 'Post not found'}), 404
# search posts

@app.route('/posts/search', methods=['GET'])
def search_posts():
    keyword = request.args.get('keyword')
    if keyword:
        posts = Post.query.filter(Post.title.contains(keyword) | Post.content.contains(keyword)).all()
        if posts:
            result = [{'id': post.id, 'title': post.title, 'content': post.content} for post in posts]
            return jsonify(result)
        else:
            return jsonify({'message': 'No posts found matching the keyword'}), 404
    else:
        return jsonify({'error': 'Missing search keyword'}), 400

@app.route('/posts/<int:id>/comments', methods=['POST'])
def create_comment(id):
    data = request.get_json()
    author = data.get('author')
    text = data.get('text')
    if author and text:
        post = Post.query.get(id)
        if post:
            new_comment = Comment(author=author, text=text, post_id=id)
            db.session.add(new_comment)
            db.session.commit()
            return jsonify({'message': 'Comment created successfully'}), 201
        else:
            return jsonify({'error': 'Post not found'}), 404
    else:
        return jsonify({'error': 'Missing author or text'}), 400

@app.route('/posts/<int:id>/like', methods=['POST'])
def like_post(id):
    post = Post.query.get(id)
    if post:
        post.likes += 1
        db.session.commit()
        return jsonify({'message': 'Post liked successfully'}), 200
    else:
        return jsonify({'error': 'Post not found'}), 404 



        
with app.app_context():
    db.create_all()




if __name__ == '__main__':
    app.run(debug=True)
