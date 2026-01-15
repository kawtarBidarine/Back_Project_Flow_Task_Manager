# Flask Authentication API

Secure authentication API with PostgreSQL backend.

## Setup

1. Clone the repository
2. Copy `.env.example` to `.env`
3. Update `.env` with credentials
4. Install dependencies: `pip install -r requirements.txt`
5. Run: `python app.py`

## Environment Variables

See `.env.example` for required configuration.

## Deployment

Configure the following in Render:
- `DATABASE_URL`: PostgreSQL connection string
- `SECRET_KEY`: Random 32+ character string
- `JWT_SECRET_KEY`: Random 32+ character string
- `ALLOWED_ORIGINS`: frontend URLs# Back_Project_Flow_Task_Manager
