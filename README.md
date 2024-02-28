# Примеры запросов

## Обновление access токена исходя из refresh токена

**Request:**
curl -X GET http://localhost:8080/refresh -H "Authorization: Bearer ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SkhWVWxFSWpvaVZHVnpkRU55WldGMFpTSXNJbVY0Y0NJNk1UY3dPVEl3TmpZMk4zMC4zT20weVBNLV9aSFZLQ2IwNjRLQm9Hc1A3Q1k3Mm51WFR6T2ZkTmdScmow"
**Output:**
{"Access Token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJHVUlEIjoiVGVzdENyZWF0ZSIsImV4cCI6MTcwOTEyMzk2NX0.Z-zOUGKoca4Ot5oDu6QBnXLbRQ4BPTydTiryhNhIdYgTGitFPYobXfxSmYiUhey4iOzthQw-Dob9AxMNCXobzg","GUID":"TestCreate"}
## Создание access и refresh токенов

**Request:**
curl -X GET http://localhost:8080/generateTokens/TestCreate
**Output:**
{"Access Token":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJHVUlEIjoiVGVzdENyZWF0ZSIsImV4cCI6MTcwOTEyMzg2N30.05uHf08FyznSYFWNaBDJ7o-_AeOMXuvohS-1lAD5m1_47zthLTHEc3HCzspp1IxD1fs-Qgk51g78CJalykqOCQ","Refresh Token":"ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SkhWVWxFSWpvaVZHVnpkRU55WldGMFpTSXNJbVY0Y0NJNk1UY3dPVEl3TmpZMk4zMC4zT20weVBNLV9aSFZLQ2IwNjRLQm9Hc1A3Q1k3Mm51WFR6T2ZkTmdScmow"}
