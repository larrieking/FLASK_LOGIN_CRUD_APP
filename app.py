from functools import wraps

from flask import session, request

from passlib.hash import   sha256_crypt
import json
import uuid
from datetime import datetime,timedelta
import jwt
import config
from bson.objectid import ObjectId

#database and app config files
app = config.configurations()
mongo = config.db_configuration()
loggedin = None





#JWT utility method
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        global loggedin #email id of authenticated user
        token = None
        if 'Authorization' in request.headers:
            header = request.headers['Authorization']
            token = header.split()[1]
            print(token)
        if not token:
            return 'Unauthorized Access!', 404

        try:

            data = jwt.decode(token, app.secret_key, options={"verify_signature":False})

            token = mongo.db.user.find({"uid":data['uid']}).limit(1)
            for t in token:
                loggedin = t["email"]
                print("loggedin"+loggedin)
            #cur.execute("SELECT * FROM registration WHERE uuid = %s ", (data['user_id'],))
            #current_user = cur.fetchone()
            #print(current_user)
            if not loggedin:
                return 'Unauthorized Access!', 403

        except:
            return 'Unauthorized Access Error!', 401
        return f(*args, **kwargs)

    return decorated




@app.route('/register', methods = ['POST'])
def register():
    msg = ''
    status = 404
    global loggedin
    input = json.loads(request.data)

    uid = str(uuid.uuid4())
    first_name = input.get('first_name')
    last_name = input.get('last_name')
    email = input.get('email')
    password = sha256_crypt.hash(input.get('password'))

    if alreadyRegistered(email):
        msg = {"Message":"email already exist"}
        status = 403
    else:

        try:

            mongo.db.user.insert_one({"first_name":first_name, "last_name":last_name, "email":email, "password":password, "uid":uid, "date_created":datetime.now().isoformat()})
            msg = {"Message":"Account Created Successfully"}
            status = 201

        except:
            msg = {"Message": "Error creating account"}
            status=403


    return app.response_class(
        response=json.dumps(msg),
        status= status,
        mimetype="application/json"

    )

@app.route("/login", methods = ["POST"])
def login():
    input = json.loads(request.data)
    email = input.get('email')
    password = input.get("password")

    person = mongo.db.user.find({"email":email}).limit(1)
    user_password = ''
    user_email = ''


    for p in person:
        print(p['email'])

        user_password = p['password']
        user_email = p['uid']

    if user_password == '' or user_email == '':
        return app.response_class(
        response=json.dumps({"message":"invalid login details"}),
        mimetype='application/json',
        status = 403
    )



    if sha256_crypt.verify(password, user_password):
        token = jwt.encode({
            'uid':user_email,
            "exp":datetime.utcnow()+timedelta(minutes=0)},
            app.secret_key
        )
        session["loggedin"]=True
        session["email"]=user_email
        status = 200


        message = {'message': "login successful", 'token': token}

    else:
        status = 403
        message= {"message":"Invalid login details"}


    return app.response_class(
        response=json.dumps(message),
        mimetype='application/json',
        status = status
    )


@app.route("/template/<string:id>", methods = ["GET"])
@token_required
def single_template(id : str):
    try:
        for data in mongo.db.template.find({"_id" : ObjectId(id)}):
            result = {"id":str(data["_id"]),"Created_by":data["Created_by"], "template_name":data["template_name"], "subject":data["subject"], "body":data["body"]}
        return app.response_class(
            response=json.dumps(result),
            mimetype='application/json',
            status=200
    )

    except Exception as e:
        return app.response_class(
            response=json.dumps({"message":repr(e)}),
            mimetype='application/json',
            status=201
        )





@app.route("/template", methods=["GET"])
@token_required
def all():
   global loggedin
   result = []
   try:
    for template in mongo.db.template.find({"Created_by":loggedin}):
        result.append({"id":str(template["_id"]),"created_by":template["Created_by"], "template_name":template["template_name"], "subject":template["subject"], "body":template["body"]})
    return app.response_class(
        response=json.dumps(result),
        mimetype='application/json',
        status=201
    )

   except Exception as e:
       return app.response_class(
           response=json.dumps({"message": repr(e)}),
           mimetype='application/json',
           status=403
       )


@app.route("/template", methods=["POST"])
@token_required
def create_template():





    global loggedin
    input = json.loads(request.data)
    template_name = input.get("template_name")
    subject = input.get("subject")
    body = input.get('body')




    try:
        mongo.db.template.insert_one({'Created_by':loggedin,"template_name":template_name, "subject":subject, "body":body})
        return app.response_class(
            response = json.dumps({"message":"success"}),
                                 mimetype="application/json",status=200)

    except Exception as e:
        return app.response_class(
            response=json.dumps({"message":repr(e)}),
            mimetype='application/json',
            status=403
        )


@app.route("/template/<string:id>", methods = ["DELETE"])
@token_required
def delete(id :str):
    global loggedin
    data = mongo.db.template.find({"_id": ObjectId(id)})
    if len(list(data.clone())) == 0:
        return app.response_class(
            response=json.dumps({"message": "The document id does not exist"}),
            mimetype='application/json',
            status=403
        )
    try:
        mongo.db.template.delete_one({"_id":ObjectId(id), "Created_by":loggedin})
        return app.response_class(
        response=json.dumps({"message": "Document Deleted Successfully"}),
        mimetype='application/json',
        status=201
    )

    except Exception as e:
        return app.response_class(
        response=json.dumps({"message": "Either the document does not exist or an error occured during deletion"}),
        mimetype='application/json',
        status=403
    )


@app.route("/template/<string:id>", methods = ["PUT"])
@token_required
def update(id : str):
    global loggedin
    input = json.loads(request.data)
    template_name = input.get("template_name")
    subject = input.get("subject")
    body = input.get("body")
    data = mongo.db.template.find({"_id": ObjectId(id)})
    if len(list(data.clone()))==0:
        return app.response_class(
            response=json.dumps({"message": "The document id does not exist"}),
            mimetype='application/json',
            status=403
        )
    try:


        mongo.db.template.update_one({"_id" : ObjectId(id), "Created_by":loggedin}, {'$set':{"template_name":template_name, "subject":subject, "body":body}})
        return app.response_class(
        response=json.dumps({"message": "Document Updated Successfully"}),
        mimetype='application/json',
        status=201
    )

    except Exception as e:
        return app.response_class(
            response=json.dumps({"message": "Either the document does  not exist or an error occured during update"}),
            mimetype='application/json',
            status=403
        )


def alreadyRegistered(email):
    find = mongo.db.user.find({'email':email})
    for mail in find:

        if email == mail["email"]:

            return True

    return False


if __name__ == '__main__':
    app.run()