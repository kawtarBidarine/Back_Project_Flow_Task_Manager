# Flow Task Manager - Backend

Backend API for **Flow Task Manager**, providing authentication and task management endpoints to support the Vue frontend.

## What this API provides

Auth module designed for a modern SPA.

Task and project domain endpoints designed to back a Kanban workflow.

Request validation, consistent error handling, and clean separation between routing, services, and data layers.

## Tech stack

Python, Flask, Flask-JWT-Extended (JWT auth), SQLAlchemy, Alembic, PostgreSQL.

If you are running locally without Postgres, you can use SQLite for development.

## API features

JWT-based authentication with login and registration.

Protected routes using access tokens.

CRUD for tasks.

Status transitions to support Kanban columns.

Optional filtering, search, and pagination patterns.

## Suggested folder structure

`app` application factory and configuration.

`models` SQLAlchemy models.

`routes` blueprints for auth and tasks.

`services` business logic.

`schemas` serialization and validation.

`migrations` Alembic migrations.

## Getting started

### Prerequisites

Python 3.10+ recommended.

A database (PostgreSQL recommended).

### Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Environment variables

Create a `.env` file.

```bash
FLASK_ENV=development
SECRET_KEY=change-me
JWT_SECRET_KEY=change-me-too
DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/flow_task_manager
```

### Run the server

```bash
flask --app app run --debug
```

## Example endpoints

`POST /auth/register`.

`POST /auth/login`.

`GET /tasks`.

`POST /tasks`.

`PATCH /tasks/{id}`.

`DELETE /tasks/{id}`.

## Local development with the frontend

Run the backend on `http://localhost:5000`.

Set `VITE_API_BASE_URL` in the frontend to match.

## Roadmap

Refresh token rotation.

Rate limiting.

API documentation via OpenAPI and Swagger UI.

Automated tests with Pytest.

## Author

Kawtar Bidarine

Portfolio https://kawtarbidarine.neocities.org/projects