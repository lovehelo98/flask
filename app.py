import os
from flask import Flask, jsonify, request, send_file, url_for
from flask_mongoengine import MongoEngine
from flask_bcrypt import Bcrypt
import jwt
import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.run(debug=True)
app.config['UPLOAD_FOLDER'] = '/Users/loveuprety/Documents/flask-auth/uploads'

app.config['MONGODB_SETTINGS'] = {
    'db': 'authentication',
    'host': 'localhost',
    'port': 27017
}
db = MongoEngine()
db.init_app(app)

class User(db.Document):
    name = db.StringField()
    email = db.EmailField()
    password = db.StringField()
    date = db.DateTimeField(default=datetime.datetime.utcnow)


    def to_json(self):
        return {
            "id": str(self.pk),
            "name": self.name,
            "email": self.email,
            "password": self.password,
            "date": str(self.date)
        }

class Comment(db.Document):
    content = db.StringField()
    name = db.StringField()

    def to_json(self):
        return{
            "id": str(self.pk),
            "name": self.name,
            "content": self.content

        }

class Post(db.Document):
    title = db.StringField()
    author = db.DictField()
    tag = db.StringField()
    comments = db.ListField(db.DictField())

    def to_json(self):
        return {
            "id": str(self.pk),
            "title": self.title,
            "author": self.author,
            "tag" : self.tag,
            "comments" : self.comments
        }

@app.route('/comment', methods=['POST'])
def addComment():
    try:
        user = User.objects.get(email="email@email.com")
        userdata = user.to_json()
        comment = Comment(content="This is comment by luv", name="Luv Uprety")
        comment.save()
        cmtdata = comment.to_json() 
        post = Post(title='newtitle' , author = userdata, tag='General', comments = [])
        post.comments.append(cmtdata)
        # post.comments.append(Comment(content="This is comment by luv", name="Luv Uprety"))
        post.save()
        comment.delete()
        posts = Post.objects.all()
        postsdata = []
        for p in posts:
            postsdata.append(p.to_json())
        return jsonify(postsdata)
    except Exception as err:
        return jsonify(error=err)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    pw_hash = bcrypt.generate_password_hash(data['password'])
    try:
        user = User(name=data['name'], email=data['email'], password=pw_hash)
        user.save()
        return jsonify(user)
    except Exception as e:
        return jsonify({'error':'Invalid data'})
        
    

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        user = User.objects.get(email=data["email"])
        validpwd = bcrypt.check_password_hash(user.password, data['password'])
        userdata = user.to_json()
        encoded_jwt = jwt.encode({"id": userdata['id']}, "secretkey", algorithm="HS256")
        if validpwd:
            return jsonify(token=encoded_jwt)
        else:
            return jsonify('invalid password')
    except Exception as e:
        return jsonify('enter valid credentials')


@app.route('/profile', methods=['GET'])
def profile():
    try:
        if(request.headers['auth-token']):
            data = jwt.decode(request.headers['auth-token'], 'secretkey', algorithms="HS256")
            user = User.objects.get(pk=data["id"])
            userdata = user.to_json()
            del userdata["password"]
            return jsonify(userdata)
        else:
            return jsonify(error="Please provide auth-token")
    except:
        return jsonify('Internal Server Error')

    
@app.route('/image/<filename>', methods=['GET'])
def sendfile(filename):
    return send_file('uploads/services/'+filename)


@app.route('/upload', methods=['POST'])
def fileUpload():
    target = os.path.join(app.config['UPLOAD_FOLDER'], 'services')
    if not os.path.isdir(target):
        os.mkdir(target)
    file = request.files['file']
    filename = secure_filename(file.filename)
    destination = "/".join([target, filename])
    file.save(destination)
    response = "Whatever you wish too return"
    return jsonify("http://"+request.host+url_for('sendfile', filename=filename))
  