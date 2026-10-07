from flask import Flask, jsonify,request
from flasgger import Swagger
from flask_cors import CORS
from dotenv import load_dotenv
import os
import math
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import jwt
from datetime   import timedelta,datetime
from functools import wraps
import re
from pymongo import ReturnDocument
import uuid
import logging

load_dotenv() # load env
SECRET_KEY = os.getenv("SECRET_KEY")


app = Flask(__name__)
#----security header - X-Content-Type-Options--X-Frame-Options--Referrer-Policy-
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response
#-----Helper function for centralized error handling----
def error_response(message,status_code):
    return jsonify({
        "message":message
    }),status_code
#---logging module config---
logging.basicConfig(
    level= logging.INFO,
    format="%(asctime)s-%(levelname)s-%(message)s"
)
logger = logging.getLogger(__name__)

#get mongo connection string
mongo_uri = os.getenv("MONGO_URI")

#connect to mongo DB
client = MongoClient(mongo_uri)

#select database... db name is TestFlask.
db = client["TestFlask"]
#select collection(products,users).
product_collections = db["products"]
user_collections = db["users"]
revoked_tokens_collection = db["revoked_tokens"]
revoked_refresh_tokens_collection = db["revoked_refresh_tokens"]

#---decorator 1 for jwt verify-----
def token_requires(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = request.headers.get("Authorization")

        if not token:
            return jsonify({
                "message": "Token is required!"
            }), 401

        parts = token.split(" ")

        if len(parts) != 2 or parts[0] != "Bearer":
            return jsonify({
                "message": "Invalid Authorization Header!"
            }), 401

        token = parts[1]

        try:
            decoded = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=["HS256"]
            )
            jti = decoded.get("jti")
            revoked_token = revoked_tokens_collection.find_one({"jti":jti})
            if revoked_token:
                return  jsonify({
                    "message":"Token has been revoked!!"
                }),401
            if decoded.get("type") != "access":
                return jsonify({
                    "message": "Access token required!"
                }), 401
            
            return f(decoded,*args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({
                "message": "Token has expired!"
            }), 401

        except jwt.InvalidTokenError:
            return jsonify({
                "message": "Invalid token or Admin access required!"
            }), 401

    return decorated
#--decorator 2-- checking user role Admin/User------
def  role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated(user,*args,**kwargs):
            if user.get("role")!= required_role :
                return jsonify({
                    "message":"Access Denied!"
                }),403
            return f(user,*args,**kwargs)
        return decorated
    return decorator


#--------------refresh_token /POST--------------
@app.route('/refresh', methods=["POST"])

def refresh_token():
    """
    Generate a new access token using a refresh token
    ---
    tags:
      - Authentication
    consumes:
      - application/json
    produces:
      - application/json

    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - refresh_token
          properties:
            refresh_token:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

    responses:
      200:
        description: New access token generated successfully
        schema:
          type: object
          properties:
            access_token:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
            role:
              type: string
              example: user

      401:
        description: Refresh token is missing, invalid, expired, or revoked

      500:
        description: Internal server error
    """

    data = request.get_json()

    refresh_token = data.get("refresh_token")

    if not refresh_token:
        return jsonify({
            "message": "Refresh token is missing"
        }), 401

    try:
        decoded = jwt.decode(
            refresh_token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        if decoded.get("type") != "refresh":
            return jsonify({
                "message": "Invalid refresh token"
            }), 401
        refresh_jti = decoded.get("jti")
        revoked_refresh_token = revoked_refresh_tokens_collection.find_one(
                {"refresh_jti":refresh_jti})
        if revoked_refresh_token :
            return jsonify({
                "message":"Refersh Token has been revoked!"
                    })
        new_access_token = jwt.encode(
            {
                "user_id": decoded["user_id"],
                "role":decoded["role"],
                "type": "access",
                "jti" : str(uuid.uuid4()),
                "exp": datetime.now() + timedelta(minutes=15)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
       
        return jsonify({
            "access_token": new_access_token,
            "role":decoded["role"]
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({
            "message": "Refresh token has expired. Please login again."
        }), 401

    except jwt.InvalidTokenError:
        return jsonify({
            "message": "Invalid refresh token"
        }), 401

# Routes -------products routes----------------------------------
#---cretaing product by Admin only----------------
@app.route('/products',methods=["POST"])

@token_requires
@role_required("admin")

def create_product(user):
    """
    Create a new product
    ---
    tags:
      - Products
    consumes:
      - application/json
    produces:
      - application/json
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
            - price
            - category
            - description
            - image
          properties:
            name:
              type: string
              example: Smart Watch
            price:
              type: number
              example: 3999
            category:
              type: string
              example: Electronics
            description:
              type: string
              example: Smart watch with fitness tracking
            image:
              type: string
              example: smartwatch.jpg
    responses:
      201:
        description: Product created successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: Product created successfully!
            id:
              type: string
              example: 68c123456789abcdef123456
      400:
        description: Invalid request or validation error
      401:
        description: Missing or invalid authentication token
      403:
        description: User is not an admin
      409:
        description: Product already exists
      500:
        description: Internal server error
    """
    data =  request.get_json(silent=True)
    if data is None:
        return jsonify({
        "message":"Invalid JSON body"
        }),400
    if not isinstance(data,dict):
      return jsonify({
          "message":"Request body must be an Json - object"
      }),400
  
    name = data.get("name")
    price = data.get("price")
    category = data.get("category")
    description = data.get("description")
    image = data.get("image")

    if not name or price is None or not category:
      return jsonify({
          "message": "All fields are required to create a product!"
      }), 400
    if not isinstance(name,str) or not name.strip():
        return jsonify({
        "message":"Product name must be a non-empty string."
    }),400
    if not isinstance (price,(int,float)) or isinstance(price,bool):
      return jsonify({
          "message":"Price must be a valid number"
      }),400
    if price<=0 :
      return jsonify({
          "message":"Price must be a positive Number!"
      }),400
    if not isinstance(category,str) or not category.strip():
      return jsonify({
          "message":"Category must be a non-empty string."
      }),400
    if not isinstance(description,str)  or not description.strip():
      return jsonify({
          "message":"Description must be a non-empty string."
      }),400
    if not isinstance(image,str) or not image.strip():
      return jsonify({
          "message":"Image field must be a non-empty string "
      })
    product ={
    "name" :name.strip(),
    "price" : price,
    "category"  :category.strip(),
    "description": description.strip(),
    "image" : image.strip()
    }
    product_exists = product_collections.find_one({"name":name})
    if product_exists:
      return jsonify({
          "message":"Product already exists!!"
      }),409
    try:
        result = product_collections.insert_one(product)
        logger.info("Product created successfully")
        return jsonify({
        "message":"Product created successfully!",
        "id":str(result.inserted_id)
    }),201
    except Exception as e:
      logger.exception("Unexpected error occured!")
      return error_response("Internal Server error",500)
     
#-------get all products--------------------------------------------
@app.route('/products',methods=["GET"])
@token_requires

def get_all_products(user):
    """
    Get all products with pagination, filtering, searching and sorting
    ---
    tags:
      - Products
    produces:
      - application/json
    security:
      - Bearer: []

    parameters:
      - name: page
        in: query
        type: integer
        required: false
        default: 1
        description: Page number

      - name: limit
        in: query
        type: integer
        required: false
        default: 10
        description: Number of products per page (maximum 100)

      - name: category
        in: query
        type: string
        required: false
        description: Filter products by category

      - name: min_price
        in: query
        type: number
        required: false
        description: Minimum product price

      - name: max_price
        in: query
        type: number
        required: false
        description: Maximum product price

      - name: search
        in: query
        type: string
        required: false
        description: Search products by name

      - name: sort
        in: query
        type: string
        required: false
        enum:
          - price_asc
          - price_desc
        description: Sort products by price

    responses:
      200:
        description: Products retrieved successfully
        schema:
          type: object
          properties:
            products:
              type: array
              items:
                type: object
                properties:
                  _id:
                    type: string
                    example: 68c123456789abcdef123456
                  name:
                    type: string
                    example: Smart Watch
                  price:
                    type: number
                    example: 3999
                  category:
                    type: string
                    example: Electronics
                  description:
                    type: string
                    example: Smart watch with fitness tracking
                  image:
                    type: string
                    example: smartwatch.jpg
            page:
              type: integer
              example: 1
            limit:
              type: integer
              example: 10
            total_products:
              type: integer
              example: 25
            total_pages:
              type: integer
              example: 3

      400:
        description: Invalid page, limit or price

      404:
        description: No products available or page exceeds available pages

      500:
        description: Internal server error
    """

    try:
        page_value = request.args.get("page")
        limit_value = request.args.get("limit")
        category = request.args.get("category")
        min_price = request.args.get("min_price")
        max_price = request.args.get("max_price")
        search = request.args.get("search")
        sort = request.args.get("sort")
        query = {}
        if category:
            query["category"] = category
        #----seach by product name-----
        if search:
            query["name"] = {
                "$regex":search,
                "$options":"i"
            }
        
        if page_value is not None:
            page = int(page_value)
        else:
            page = 1
        if limit_value is not None:
            limit = int(limit_value)
        else:
            limit = 10
        skip= (page-1)*limit

        if page<=0:
            return error_response("Page number is invalid",400)
        if limit<=0 or limit>100:
            return error_response("Invalid product limit",400)
        if min_price is not None:
            min_price = float(min_price)

        if max_price is not None:
             max_price = float(max_price)
      
        if min_price is not None and min_price<0:
                return error_response("Minimum price must be a positive number",400)
        if max_price is not None and max_price<=0 :
                return error_response(
                "Maximum price must be a positive number!",400 )
        if min_price is not None and max_price is not None :
            if min_price > max_price:
                return error_response(
                    "Minimum price must be less than maximum price",400)
        price_query = {}
        if min_price is not None:
                price_query["$gte"] = float(min_price)
        if max_price is not None:
                price_query["$lte"] = float(max_price)
        if price_query:
                query["price"] = price_query

        total_products = product_collections.count_documents(query)
        total_pages = math.ceil(total_products/limit) if total_products else 0
        if total_products==0:
            return error_response("No products Available",404)
        if page > total_pages :
            # Total products 0 means page=1.; 1>0 chance is there.
            return error_response(
                "Page number exceeds available pages!!",404)
       
        if sort is not None:
            if sort not in ["price_asc","price_desc"]:
                return error_response("Invalid sort option",400)
        sort_field = None
        sort_order = 1
        if sort == "price_asc":
            sort_field = "price"
            sort_order = 1
        elif sort == "price_desc" :
            sort_field = "price"
            sort_order = -1
        products = product_collections.find(query)

        if sort_field:
            products = products.sort(sort_field, sort_order)

        products = products.skip(skip).limit(limit)

        products = list(products)
        for product in products:
            product["_id"] = str(product["_id"])
        logger.info("Products fetched successfully")

        return jsonify(
           
            {
            "products": products,
            "page": page,
            "limit" : limit,
            "total_products" : total_products,
            "total_pages":total_pages
            }),200
    except ValueError:
        return error_response("Invalid page, limit or price.",400)
   
   
    except Exception as e:
        logger.exception("Unexpected error occured!")
        return error_response("Something went wrong!!!",500)
#------------------------------------------------------------------------------

@app.route('/products/<product_id>',methods=["GET"])  
@token_requires 
def get_single_product(user,product_id):
    try:
        if not ObjectId.is_valid(product_id):
            return  jsonify({
                "message":"Invalid product Id"
            }),400
        product = product_collections.find_one(
            {"_id":ObjectId(product_id)}
            )
        if product is None:
            return jsonify({"message":"Product not found!"}),404
    
        product["_id"] = str(product["_id"])
        return jsonify(product),200
    except Exception as e:
       logger.exception("Unexpected error")
       return error_response("Something went wrong",500)
#-----------------update product by admin only----------------------------
@app.route('/products/<product_id>',methods=["PUT"])
@token_requires
@role_required("admin")

def update_product(user, product_id):
    """
    Update an existing product
    ---
    tags:
      - Products
    consumes:
      - application/json
    produces:
      - application/json
    security:
      - Bearer: []

    parameters:
      - name: product_id
        in: path
        required: true
        type: string
        description: MongoDB ObjectId of the product
        example: 68c123456789abcdef123456

      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
            - price
            - category
            - description
            - image
          properties:
            name:
              type: string
              example: Smart Watch Pro
            price:
              type: number
              example: 4999
            category:
              type: string
              example: Electronics
            description:
              type: string
              example: Updated smart watch with advanced fitness tracking
            image:
              type: string
              example: smartwatch-pro.jpg

    responses:
      200:
        description: Product updated successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: Product updated successfully
            product:
              type: object
              properties:
                _id:
                  type: string
                  example: 68c123456789abcdef123456
                name:
                  type: string
                  example: Smart Watch Pro
                price:
                  type: number
                  example: 4999
                category:
                  type: string
                  example: Electronics
                description:
                  type: string
                  example: Updated smart watch with advanced fitness tracking
                image:
                  type: string
                  example: smartwatch-pro.jpg

      400:
        description: Invalid product ID, JSON data, or product field

      401:
        description: Missing or invalid authentication token

      403:
        description: User is not an admin

      404:
        description: Product does not exist

      500:
        description: Internal server error
    """

    try:
        if not ObjectId.is_valid(product_id):
            return jsonify({
                "message":"Invalid Product Id"
            }),400
        
        data = request.get_json()
        if data is None:
            return jsonify({
                "message":"Invalid Json data given!"
            }),400
        name = data.get("name")
        price  =data.get("price")
        category = data.get("category")
        description = data.get("description")
        image = data.get("image")

        if not isinstance(name,str) or not name.strip():
            return jsonify({
                "message":"Product name must be a non-empty string"
            }),400
        if not isinstance(price,(int,float)) or price<=0 :
            return jsonify({
                "message":"Price must be a valid positive number"
            }),400
        if not isinstance(category,str) or not category.strip():
            return jsonify({
                "message":"Category must be a non-empty string"
            }),400
        if not isinstance(description,str) or not description.strip():
            return jsonify({
                "message":"Description must be a non-empty string!"
            }),400
        if not isinstance (image,str) or not image.strip():
            return jsonify({
                "message":"Image URL must be a non empty string!"
            }),400
        name = name.strip()
        category = category.strip()
        description = description.strip()
        image = image.strip()
        
        product = product_collections.find_one_and_update(
            {"_id":ObjectId(product_id)},
            {"$set":{
                "name":name,
                "price":price,
                "category":category,
                "description":description,
                "image":image
                       
            }},
            return_document = ReturnDocument.AFTER
        )
        logger.info("Product updated successfully")
        if product is None:
            logger.warning("Update failed: product not found")
            return jsonify({"message":"No such product exists!"}),404
        
        product["_id"] = str(product["_id"])
        return jsonify({
            "message":"Product updated successfully",
            "product":product
        }),200
    except Exception:
        return jsonify({
            "message":"Something went wrong!"
        }),500

@app.route('/products/<product_id>',methods=["DELETE"])
@token_requires
@role_required("admin")

def delete_product(user, product_id):
    """
    Delete an existing product
    ---
    tags:
      - Products
    produces:
      - application/json
    security:
      - Bearer: []

    parameters:
      - name: product_id
        in: path
        required: true
        type: string
        description: MongoDB ObjectId of the product
        example: 68c123456789abcdef123456

    responses:
      200:
        description: Product deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
              example: Product deleted!

      400:
        description: Invalid product ID

      401:
        description: Missing or invalid authentication token

      403:
        description: User is not an admin

      404:
        description: Product does not exist

      500:
        description: Internal server error
    """
    try:
        logger.info("Delete product request received")
        if not ObjectId.is_valid(product_id):
            return jsonify({
                "message":"Invalid product Id"
            }),400
        
        product = product_collections.find_one_and_delete(
            {
                "_id":ObjectId(product_id)
            }
        )

        if product is None:
            logger.warning("Delete failed: product not found")
            return jsonify({
                "message":"No such product exists!"
            }),404
        logger.info("Product deleted successfully")
        return jsonify({
            "message":"Product deleted!"
        }),200

    except Exception:
        return jsonify({
            "message":"Something went wrong.Cant delete the product."
        }),500

#.......user collection routes-------------------------------------------

@app.route('/register',methods=["POST"])
def register():
   
    data=request.get_json()
    name=data.get("name")
    email=data.get("email")
    password=data.get("password")
    if not name or not email or not password:
        return jsonify({
            "message":"All fields are required !"
        })
    if not isinstance(name,str):
        return jsonify({
            "message":" Name must be a string!"
        }),400
    if not isinstance(email,str):
        return jsonify({
            "message":"Email must be a string"
        }),400
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(email_pattern,email):
        return jsonify({
            "message":"Please enter a valid Email ID."
        }),400
    if len(password)<6:
        return jsonify({
            "message":"Password must be 6 character long!"
        }),400

    email_exists = user_collections.find_one({"email":email})
    if email_exists:
        return jsonify({
            "message":"Email exists!!"
        })
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )
    user = {
        "name":name,
        "email":email,
        "password":hashed_password.decode("utf-8"),
        "role":"user"
    }
   
    result = user_collections.insert_one(user)
    user["_id"] = str(result.inserted_id)
    return jsonify({
        "message":"User created successfully!"
        
    },user),201

@app.route('/login',methods=["POST"])
def login():
    """
     User Login
     ---
     tags:
       - Authentication
     consumes:
       - application/json
     produces:
       - application/json
     parameters:
       - in: body
         name: body
         required: true
         schema:
           type: object
           required:
             - email
             - password
           properties:
             email:
               type: string
               example: tester@gmail.com
             password:
               type: string
               example: tester123
     responses:
       200:
         description: Login successful
         schema:
           type: object
           properties:
             message:
               type: string
               example: Login successful
             user_id:
               type: string
               example: 68c123456789abcdef123456
             name:
               type: string
               example: Ritta
             email:
               type: string
               example: tester@gmail.com
             role:
               type: string
               example: user
             access_token:
               type: string
               example: eyJhbGciOiJIUzI1NiIs...
             refresh_token:
               type: string
               example: eyJhbGciOiJIUzI1NiIs...
       401:
         description: Invalid credentials or user does not exist
     """       
    data=request.get_json()

    email = data["email"]
    password = data["password"]
    
    user = user_collections.find_one({
        "email": email
    })
   
    if user is None:
        return jsonify({
            "message":"No such user exists!"
        }),401

    if not bcrypt.checkpw(
        password.encode("utf-8"),
        user["password"].encode("utf-8")):
        logger.warning("Login failed: invalid credentials")
        return jsonify({
            "message":"Invalid credentials!"
        }),401
    access_token = jwt.encode(
        {
         "user_id":str(user["_id"]),
         "role" : user["role"],
         "type":"access", 
         "jti": str(uuid.uuid4()),
         "exp":datetime.now()+timedelta(minutes=15)
         },
         SECRET_KEY,
         algorithm="HS256"
    )
    refresh_token = jwt.encode(
        {
        "user_id":str(user["_id"]),
        "type":"refresh",
        "role":user["role"],
        "jti": str(uuid.uuid4()),
        "exp":datetime.now()+timedelta(days=7)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    logger.info("User login successful")

    return jsonify({
       "message": "Login successful",
        "user_id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
        "role":user["role"],
        "access_token":access_token,
        "refresh_token":refresh_token
    }),200

#--------user logout--------revoke access_token--------------
@app.route('/logout',methods=["POST"])
@token_requires

def logout(decoded):
    """
    Logout user and revoke access and refresh tokens
    ---
    tags:
      - Authentication
    consumes:
      - application/json
    produces:
      - application/json
    security:
      - Bearer: []

    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - refresh_token
          properties:
            refresh_token:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

    responses:
      200:
        description: Logout successful
        schema:
          type: object
          properties:
            message:
              type: string
              example: Logout successfully!

      400:
        description: Refresh token is missing from request body

      401:
        description: Access token or refresh token is invalid or missing

      500:
        description: Internal server error
    """

    try:
        jti = decoded.get("jti")
        revoked_token = revoked_tokens_collection.insert_one({"jti":jti})

        data = request.get_json(silent=True)
        if not data:
            return jsonify({
                "message":"Refresh token missing!"
            }),400
        refresh_token = data.get("refresh_token")
        if not refresh_token:
            return jsonify({
                "message":"Refresh token is required for logout!"
            }),401

        refresh_decoded = jwt.decode(
            refresh_token,
            SECRET_KEY,
            algorithms=["HS256"]
        )
        refresh_jti = refresh_decoded.get("jti")
        revoked_refresh_token = revoked_refresh_tokens_collection.insert_one({
            "refresh_jti":refresh_jti
        })
        
        if not revoked_token:
            return jsonify({
                "message":"Token missing or JTI is Invalid"
            }),401
        if not revoked_refresh_token:
            return jsonify({
                "message":"Refresh token JTI is missing!"
            }),401
        return jsonify({
            "message":"Logout successfully!"
        }),200
    except Exception:
        return jsonify({
            "message":"Something went wrong while Logout!"
        }),500
#-----centralized error handler for Http errors-----
@app.errorhandler(404)
def error_handler_404(error):
    return error_response("Resource not found!",404)
@app.errorhandler(405)
def error_handler_405(error):
    return error_response("Method not Allowed!",405)
@app.errorhandler(500)
def error_handler_500(error):
    return error_response("Internal server error!",500)

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Flask Product API",
        "description": "API documentation for authentication and products",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Enter: Bearer <your_access_token>"
        }
    }
}

swagger = Swagger(app, template=swagger_template)

if __name__ == "__main__":
    port = int(os.getenv("PORT",5000))
    app.run(host="0.0.0.0",port=port,debug=True)
