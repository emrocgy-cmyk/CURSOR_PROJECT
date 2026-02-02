# CURSOR_PROJECT

Simple in-memory authentication logic with sign-up, login, and logout.

## Usage

```python
from auth import AuthService, AuthError

auth = AuthService(min_password_length=8)

auth.sign_up("alice", "my-secret-pass")
token = auth.login("alice", "my-secret-pass")

current_user = auth.get_current_user(token)
print(current_user)  # "alice"

auth.logout(token)
```
