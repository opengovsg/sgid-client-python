# Flask example sgID app

The example application code is in `app.py`. You can copy this code to bootstrap your sgID client application, and run this app locally to understand how this SDK helps you interact with the sgID server.

## Running this example app locally

### Prerequisites

**Register a new sgID client**

Go to the [sgID developer portal](https://developer.id.gov.sg) and [register a new client](https://docs.id.gov.sg/introduction/getting-started/register-your-application).

Use the following details to register:

1. For "Name", enter any test name (there is no limit to the number of clients you can create)
2. For "Description", enter any
3. Under "Scopes", add "NAME"
4. Under "Callback URLs", add the following:

```
http://localhost:5001/api/callback
```

### Running the server

1. Clone this repo.

```
git clone https://github.com/opengovsg/sgid-client-python.git
```

2. Go to this folder (`examples/flask`) and copy the contents of `.env.example` into a new file called `.env`.

```
cd sgid-client-python/examples/flask
cat .env.example > .env
```

3. Replace the values in `.env` with the credentials of your sgID client (see [Prerequisites](#prerequisites)).

4. Run:

```
pip install -r requirements.txt
flask run
```

This should start the server on port 5001.

### Serving the frontend

sgID provides an [example frontend](https://github.com/opengovsg/sgid-demo-frontend-spa) which you can use to interact with the server in `app.py`. Follow the instructions in that repo to run the example frontend.

## For contributors

### Local development

To start the server in debug mode, run:

```
flask run --debug
```

### Adding dependencies

This project's depdencies are managed using [Poetry](https://python-poetry.org/). However, the project also includes a `requirements.txt` so that those who wish to run the app locally don't need to install [Poetry](https://python-poetry.org/) first.

To add a dependency, first run:

```
poetry add <your-dependency-name>
```

Then update the `requirements.txt`:

```
poetry export --output requirements.txt
```
