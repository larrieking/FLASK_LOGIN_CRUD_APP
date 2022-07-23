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
        #check if request headers are set
        if 'Authorization' in request.headers:
            header = request.headers['Authorization']
            token = header.split()[1]
            print(token)
        #if no request header, quit with 404
        if not token:
            return 'Unauthorized Access!', 404

        try:
            #decode JWT token
            data = jwt.decode(token, app.secret_key, options={"verify_signature":False})
            #validate the token
            token = mongo.db.user.find({"uid":data['uid']}).limit(1)
            for t in token:
            #store  email address of logged in user in variable
                loggedin = t["email"]

            #if not validate, quit the app with 403 error
            if not loggedin:
                return 'Unauthorized Access!', 403

        except:
            return 'Unauthorized Access Error!', 401
        return f(*args, **kwargs)

    return decorated


@app.route('/register', methods = ['POST'])
def register():
    '''An endpoint to register new user in the users table'''
    #current logged in user
    global loggedin

    #get the json data from the request
    input = json.loads(request.data)

    #UUID for generating JWT
    uid = str(uuid.uuid4())

    #get the input parameters from the request
    first_name = input.get('first_name')
    last_name = input.get('last_name')
    email = input.get('email')
    password = sha256_crypt.hash(input.get('password'))

    #if the paramers are incomplete, respond with status 403
    if not first_name or not last_name or not email or not password:
        return app.response_class(
            response=json.dumps({"Message":"Please submit the correct json data"}),
            status=403,
            mimetype="application/json"


        )





    #check if user is already registered and notify accordingly
    if alreadyRegistered(email):
        msg = {"Message":"email already exist"}
        status = 403
    else:

        try:
            #if user is not yet registered, go ahead and register him/her
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
    '''endpoint for authenticating user'''
    #get the request param
    input = json.loads(request.data)
    email = input.get('email')
    password = input.get("password")
    #check if the param are complete/correct
    if not email or not password:
        return app.response_class(
            response=json.dumps({"Message":"Please provide email and password in json format"}),
            status=403,
            mimetype="application/json"
        )
    #fetch the email from the database
    person = mongo.db.user.find({"email":email}).limit(1)
    user_password = ''
    user_email = ''


    for p in person:


        user_password = p['password']
        user_email = p['uid']
    #if the password are incorrect, quit the app
    if user_password == '' or user_email == '':
        return app.response_class(
        response=json.dumps({"message":"invalid login details"}),
        mimetype='application/json',
        status = 403
    )


    #Generate JWT token
    if sha256_crypt.verify(password, user_password):
        token = jwt.encode({
            'uid':user_email,
            "exp":datetime.utcnow()+timedelta(minutes=0)},
            app.secret_key
        )
        #create session variables
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
    #current logged in user
    global loggedin
    '''endpoint for getting single template entry'''
    try:
        #look up the template record from the db using its id
        for data in mongo.db.template.find({"_id" : ObjectId(id), "Created_by":loggedin}):
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
   '''endpoint for getting all registered templates'''
   global loggedin
   #result stores all registered templates
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

    '''endpoint for creating template'''



    global loggedin #current user email
    # get json data from the request
    input = json.loads(request.data)
    template_name = input.get("template_name")
    subject = input.get("subject")
    body = input.get('body')


    #check if all the variables are contained in the post request
    if not template_name or not subject or not body:
        return app.response_class(response=json.dumps({"Message":"Please submit the correct json data"}),
                                  status=403,
                                  mimetype='application/json')


    try:
        #if json variable are complete, create the template
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
    '''endpoint for deleting record from the db'''
    global loggedin
    data = mongo.db.template.find({"_id": ObjectId(id), "Created_By":loggedin})
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
    '''endpoint for updating the template document'''
    global loggedin
    input = json.loads(request.data)
    template_name = input.get("template_name")
    subject = input.get("subject")
    body = input.get("body")
    #check if the record exist in the database first
    data = mongo.db.template.find({"_id": ObjectId(id)})
    if len(list(data.clone()))==0:
        return app.response_class(
            response=json.dumps({"message": "The document id does not exist"}),
            mimetype='application/json',
            status=403
        )
    try:

        #if the record exist then carry out the update
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
    '''utility method for checking if an email already exist'''
    find = mongo.db.user.find({'email':email})
    for mail in find:

        if email == mail["email"]:

            return True

    return False


if __name__ == '__main__':
    app.run()