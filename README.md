# Identity Broker 

Identity and Group Management service that supports Single Sign On through OAuth2 and external ID providers,
such as Google, Azure AD, and Line.

---
## Docs
- spec: https://www.notion.so/4c1f17cae16c4b2487fcfb8e8ae6a8b8?v=8f48d2b873d84173bcea58db3f2f5418&pvs=4


## Env Variables
| Name                | Value                                     | Module   | Remarks |
|---------------------|-------------------------------------------|----------|---------|
| LOGOUT_REDIRECT_URL | https://adp.yinlong.link/account/login/   | Identity | 登出後的頁面  |
| LOGIN_REDIRECT_URL  | https://adp.yinlong.link/account/profile/ | Identity | 登入後的頁面  |
