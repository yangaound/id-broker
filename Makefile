format:
	autoflake -ir --remove-all-unused-imports .
	isort .
	black .

lint:
	flake8

migrate:
	python manage.py makemigrations
	python manage.py migrate

run:
	gunicorn id_broker.wsgi
