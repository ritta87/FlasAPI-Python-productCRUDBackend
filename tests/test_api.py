import sys
import os
import pytest
import jwt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app
from app import (
    SECRET_KEY,
    revoked_tokens_collection,
    revoked_refresh_tokens_collection
)

#--fixture---
@pytest.fixture
def client():
    return app.test_client()

def test_app_exists():
    assert app is not None

#test 1 - no jwt - /products GET-
def test_get_products_without_token(client):
    response  = client.get('/products')
    assert response.status_code == 401
#-----user login--return access token---
def test_login_success(client):
    response = client.post('/login',
                          json={
                              "email":"tester@gmail.com",
                              "password":"tester123"
                          })
    assert response.status_code == 200
    data = response.get_json()
    assert "access_token" in data
    assert "refresh_token" in data
#--user login access protected route with access token----
def get_login_access_token(client):
    login_response = client.post('/login',
                   json =
                     {
                    "email":"tester@gmail.com",
                    "password":"tester123"}
                    )
    assert login_response.status_code == 200
    data = login_response.get_json()
    access_token = data["access_token"]

#--use token to access /products route---
    response = client.get('/products',
                          headers ={
                              "Authorization":f"Bearer {access_token}"
                          })
    assert response.status_code == 200

#---test invalid login with wrong password---
def test_invalid_login_success(client):
    response = client.post('/login',
                           json = {
                               "email":"tester@gmail.com",
                               "password":"wrongpwd123"
                           })
    assert response.status_code == 401

#---fake tampered token-----
def test_get_with_invalid_token(client):    
    response = client.get('/products',
                          headers={"Authorization":"Bearer invalid_tampered_token"})
    assert response.status_code == 401
    
#---if email Id  does not exists---
def test_email_donot_exists(client):
    response = client.post('/login',
                 json = {
                    "email":"donotexists@gmail.com",
                    "password":"tester123"
                    })
    assert response.status_code == 401

#----logout-----------
def test_logout_with_revoked_token(client):
    login_response = client.post('/login',
                    json = {
                        "email":"tester@gmail.com",
                        "password":"tester123"
                    })
    login_response.status_code == 200
    data = login_response.get_json()
    access_token = data["access_token"]
    refresh_token = data["refresh_token"]
     #decode access token and get its JTI
    access_decoded = jwt.decode(
        access_token,
        SECRET_KEY,
        algorithms=["HS256"]
    )

    access_token_jti = access_decoded["jti"]

    #Decode refresh token and get its JTI
    refresh_decoded = jwt.decode(
        refresh_token,
        SECRET_KEY,
        algorithms=["HS256"]
    )
    refresh_jti = refresh_decoded["jti"]

    logout_response = client.post('/logout',
                                  json={
                                    "refresh_token":refresh_token},
                                  headers=
                                  {"Authorization":f"Bearer {access_token}"})
    
    assert logout_response.status_code == 200

    # Check access-token JTI was added to revoked_tokens
    revoked_access = revoked_tokens_collection.find_one({
        "jti": access_token_jti
    })

    assert revoked_access is not None

    # Check refresh-token JTI was added to revoked_refresh_tokens
    revoked_refresh = revoked_refresh_tokens_collection.find_one({
        "refresh_jti": refresh_jti
    })

    assert revoked_refresh is not None

#-------- check refresh token POST works---
def test_refresh_token(client):
    login_response = client.post('/login',
                                 json ={
                                     "email":"tester@gmail.com",
                                     "password":"tester123"
                                 })
    assert login_response.status_code == 200
    data = login_response.get_json()
    refresh_token = data["refresh_token"]
    refresh_response = client.post('/refresh',
                                   json={
                                       "refresh_token":refresh_token
                                   })
    refresh_data = refresh_response.get_json()
    assert "access_token" in refresh_data
    assert refresh_response.status_code == 200

#--revoked refresh token should be rejected-------------
def test_revoked_refresh_reject(client):

    login_response = client.post(
        "/login",
        json={
            "email": "tester@gmail.com",
            "password": "tester123"
        }
    )

    assert login_response.status_code == 200

    data = login_response.get_json()

    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # Logout → revoke refresh token
    logout_response = client.post(
        "/logout",
        headers={
            "Authorization": f"Bearer {access_token}"
        },
        json={
            "refresh_token": refresh_token
        }
    )

    assert logout_response.status_code == 200

    # try  the revoked refresh token
    refresh_response = client.post(
        "/refresh",
        json={
            "refresh_token": refresh_token
        }
    )

    assert refresh_response.status_code == 401
#----a normal cant create a product------
def test_user_not_allowed_create_product(client):
    user_login_response = client.post('/login',
                                  json =    {
                                   "email":"tester@gmail.com",
                                   "password":"tester123"
                                      })
    assert user_login_response.status_code==200
    data = user_login_response.get_json()
    access_token = data["access_token"]
    role = data["role"]
    assert role != "admin"
    create_product_res = client.post('/products',
                                       headers={
                        "Authorization": f"Bearer {access_token}"
                                            })
    assert create_product_res.status_code == 403
#--------Test admin if role admin can create a product-------
def tset_admin_can_create_product(client):
    login_response = client.post('/login',
                                 json={
                                     "email":"admin@gmail.com",
                                     "password":"admin123"
                                 })
    assert login_response.status_code == 200

    data = login_response.get_json()
    access_token = data["access_token"]
    role = data["role"]
    assert role == "admin"
    admin_creata_product_response = client.post('/products',
                      json={
            "name": "Test Smart Watch",
            "price": 2500,
            "category": "Electronics",
            "image": "watch.jpg"
        },
        headers={
            "Authorization": f"Bearer {access_token}"
        })
    assert admin_creata_product_response.status_code == 201
    
    
def test_user_not_allowed_to_update_product(client):
    user_login_response = client.post('/login',
                                  json =    {
                                   "email":"tester@gmail.com",
                                   "password":"tester123"
                                      })
    assert user_login_response.status_code==200
    data = user_login_response.get_json()
    access_token = data["access_token"]
    role = data["role"]
    assert role != "admin"
    update_product_res = client.put(
        "/products/6ab4afbf9cadf9910b379869",
        json={
            "price": 30000
        },
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    assert update_product_res.status_code == 403

def test_user_not_allowed_to_delete_product(client):
    user_login_response = client.post('/login',
                                  json =    {
                                   "email":"tester@gmail.com",
                                   "password":"tester123"
                                      })
    assert user_login_response.status_code==200
    data = user_login_response.get_json()
    access_token = data["access_token"]
    role = data["role"]
    assert role != "admin"
    delete_product_res = client.delete(
        "/products/6ab4afbf9cadf9910b379869",
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    assert delete_product_res.status_code == 403

#----admin allowed to update product-------
def test_admin_allowed_to_update_product(client):
    admin_login_response = client.post('/login',
                                  json =    {
                                   "email":"admin@gmail.com",
                                   "password":"admin123"
                                      })
    assert admin_login_response.status_code==200
    data = admin_login_response.get_json()


    access_token = data["access_token"]
    role = data["role"]
    assert role == "admin"
    update_product_res = client.put(
        "/products/6ab4b1469cadf9910b37986b",
    json={
            "category": "updated Headset and Buds",
            "description": "updated Advance Metal Wired Earbuds",
            "image": "https://m.media-amazon.com/images/I/71nl7rG3ynL._AC_SL1500_.jpg",
            "name": "updated Ear bud Mp XPro",
            "price": 9999
        },
    
    headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    assert update_product_res.status_code == 200

#----admin able to delete product----
def test_admin_allowed_to_delete_product(client):
    login_response = client.post('/login',
                                  json =    {
                                   "email":"admin@gmail.com",
                                   "password":"admin123"
                                      })
    assert login_response.status_code==200
    data = login_response.get_json()
    access_token = data["access_token"]
    role = data["role"]
    assert role == "admin"
    delete_product_res = client.delete(
        "/products/6ab4afbf9cadf9910b379869",
        headers={
            "Authorization": f"Bearer {access_token}"
        }
    )
    assert delete_product_res.status_code == 200
#--------Read a single product selected by admn and user--
def test_read_single_product_product_id_valid_token(client):
    login_response = client.post('/login',
               json= {
                "email":"tester@gmail.com",
                "password":"tester123"
                })
    data = login_response.get_json()
    access_token = data["access_token"]
    assert login_response.status_code == 200
    read_single_product_res = client.get('/products/6ab4b1469cadf9910b37986b',
                            headers = {
                                "Authorization":f"Bearer {access_token}"
                            })
    assert read_single_product_res.status_code == 200
#---invalid nonexistent product--------
def test_non_existent_product(client):
    login_response = client.post('/login',
                   json= {
                    "email":"tester@gmail.com",
                    "password":"tester123"
                    })
    data = login_response.get_json()
    access_token = data["access_token"]
    assert login_response.status_code == 200
    non_existent_product_response = client.get('/products/123456789',
                    headers={
                        "Authorization":f"Bearer {access_token}"})
    assert non_existent_product_response.status_code == 400