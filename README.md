# Identity Broker 

Identity and Group Management service that supports Single Sign On through OAuth2 ID providers,
such as `Google`, `Microsoft`, and `Line`.

---
## Docs
- https://www.notion.so/4c1f17cae16c4b2487fcfb8e8ae6a8b8?v=8f48d2b873d84173bcea58db3f2f5418&pvs=4


## Env Variables
| Name                | Value                                               | Remarks     |
|---------------------|-----------------------------------------------------|-------------|
| SECRET_KEY          | 8e8ae6a8b8?v=8f48d2b873d84173bcea58db3f2f5418&pvs=4 |             |
| LOGOUT_REDIRECT_URL | https://adp.yinlong.link/account/login/             | 登出後的頁面  |
| LOGIN_REDIRECT_URL  | https://adp.yinlong.link/account/profile/           | 登入後的頁面  |


 See: `id_broker/env.py`

---
## Features

### Account Management

<details>
  <summary> Account Sign-Up </summary>

  ```bash
  BaseURL=http://localhost:8000
  
  curl -sX POST "${BaseURL}/account/sign-up/" \
  -H "Content-Type: application/json" \
  -d '{"email": "fofx@outlook.com", "password": "abc+123", "first_name": "Y"}' \
  -w '%{http_code}\n' | jq
  ```
</details>


<details>
  <summary> Account Confirmation (Email Activation Link) </summary>

  ```shell
  curl "${BaseURL}/account/perform-confirmation/?activate_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb2Z4QG91dGxvb2suY29tIn0.BsrV7qMLGk41ZDdoYzSIPnXMjxidWNhvqP-U2bPRjBo&verification_code=1700795753989973"
  ```
</details>


<details><summary> Builtin-User Login: Set session cookies </summary>
    
    Navigate to the login page "${BaseURL}/account/login/"
</details>


<details><summary> Builtin-User(Client) Password Login: Set session cookies</summary>
  
1. Retrieve CSRF Token 
  
    The CSRF token is set by the backend server in a cookie when the user first visits the server. 
    It's then sent back to the server on subsequent requests to verify that the request is legitimate.

    ```bash
    CSRFToken=$(curl -s "${BaseURL}/security/csrf-token/" | jq -r .csrftoken)
    echo "Retrieved: $CSRFToken"
    ```
        
2. Login Request with the CSRF Token 
    ```bash
    curl -sX POST "${BaseURL}/account/client-password-login/" \
    -H "Content-Type: application/json" \
    -H "X-CSRFTOKEN: $CSRFToken" \
    -b "csrftoken=$CSRFToken" \
    -d '{"email": "fofx@outlook.com", "password": "abc+123"}' \
    -w 'http_code=%{http_code}\n' \
    -c idb-http.cookie
    ```
            
3. Login Implementation:
    ```html
    <script>
        const form = document.querySelector('#login-form');
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
      
            const payload = {
                email: document.querySelector('#email').value,
                password: document.querySelector('#password').value,
            }
      
            const axiosConfig = {
                withCredentials: true,
                xsrfCookieName: 'csrftoken',
                xsrfHeaderName: 'X-CSRFTOKEN',
                baseURL: 'https://idb.azurewebsites.net'
            };
      
            try {
                /*
                The CSRF token is set by the backend server in a cookie when the user first visits the server.
                It's then sent back to the server on subsequent requests to verify that the request is legitimate.
                */
                const csrfToken = (await axios.get('/account/csrf-token/', axiosConfig)).data.csrftoken;
                // replace with your login endpoint
                const response = await axios.post('/account/client-password-login/', payload, Object.assign({headers: {'X-CSRFTOKEN': csrfToken}}, axiosConfig));
                console.log('Login successful!');
                // TODO: redirect the user to the order's dashboard
            } catch (error) {
                console.error('Login failed!', error);
                // TODO: show an error message to the user
            }
        });
    </script>
    ```
</details>


<details><summary> Logout: Clears the session cookie</summary>
  
    Navigate to "${BaseURL}/account/logout/"
</details>


<details>
  <summary> Retrieve Current User Profile </summary>

  ```bash
  curl -s "${BaseURL}/account/profile/" \
  -w "%{http_code}\n" \
  -b idb-http.cookie | jq
  ```
  > *TIP*:
  > - The `user_identifier` may originate from external Identity Providers, represented as the claim `sub`.
  > - The `full_name` is consist of the `first_name` and `last_name` in the 'builtin-user-pool'
  > - The `full_name` is the `name` originating from an external Identity Provider, where the `first_name` and `last_name` may be blank.
  > - 403 or 401 for failure
</details>


<details><summary> Modify Personal Info </summary>

  ```bash
  curl -skX PATCH "${BaseURL}/account/update-user-info/" \
  -H "Content-Type: application/json" \
  -H "X-CSRFTOKEN: $CSRFToken" \
  -b "csrftoken=$CSRFToken" \
  -d '{"first_name": "Y", "last_name": "YY"}' \
  -w '%{http_code}\n' -b idb-http.cookie | jq
  ```
</details>


### Security


<details><summary> Retrieve CSRF Token </summary>
  
  ```bash
  curl -s "${BaseURL}/security/csrf-token/" | jq
  ```
</details>



<details><summary> Change Password </summary>

  ```bash
  curl -skX PATCH "${BaseURL}/security/change-password/" \
  -H "Content-Type: application/json" \
  -H "X-CSRFTOKEN: $CSRFToken" \
  -b "csrftoken=$CSRFToken" \
  -d '{"password": "abc+123", "new_password": "abc+123"}' \
  -w '%{http_code}\n' -b idb-http.cookie -c idb-http.cookie | jq
  
  CSRFToken=$(curl -s "${BaseURL}/security/csrf-token/" | jq -r .csrftoken)
  ```
</details>


<details><summary> Forget-password </summary>

  ```bash
  curl -sX POST ${BaseURL}/security/activate-password-reset/ \
  -d "email=fofx@outlook.com"  \
  -w '%{http_code}\n' | jq
  ```
</details>


<details><summary> Reset Password  </summary>

- Click link on the received email (for debugging purposes) 
  ```text
  ${BaseURL}/security/perform-reset-password/?reset_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb2Z4QG91dGxvb2suY29tIn0.BsrV7qMLGk41ZDdoYzSIPnXMjxidWNhvqP-U2bPRjBo&verification_code=1700796813320016&new_password=abc%2B123
  ```
    
- cURL POST request 
  ```bash
  curl -sX POST "${BaseURL}/security/perform-password-reset/" \
  -d reset_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb2Z4QG91dGxvb2suY29tIn0.BsrV7qMLGk41ZDdoYzSIPnXMjxidWNhvqP-U2bPRjBo \
  -d verification_code=1700856614827042 \
  -d new_password=abc%2B123 \
  -w '%{http_code}\n' | jq
  ```
</details>


### Group & Permission Management

<details><summary>  Admin Site(Django Admin) </summary>

    Navigate to "${BaseURL}/admin/"
</details>
