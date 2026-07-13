Root project: [bidly](https://github.com/aididalam/bidly)

# Endpoints

| Method | Path | Authentication |
|---|---|---|
| POST | `/api/auth/register` | No |
| POST | `/api/auth/login` | No |
| POST | `/api/auth/logout` | Bearer JWT |
| GET | `/api/auth/me` | Bearer JWT |

# Structure

```text
auth/
├── Dockerfile
├── compose.yaml
├── cmd/api/
├── internal/
│   ├── config/
│   ├── handler/
│   ├── middleware/
│   ├── model/
│   ├── repository/
│   ├── service/
│   └── token/
└── migrations/
```
