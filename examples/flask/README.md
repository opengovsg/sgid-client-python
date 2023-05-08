# Flask example sgID app

The example application code is in `app.py`. You can copy this code to bootstrap your sgID client application, and run this app locally to understand how this SDK helps you interact with the sgID server.

## Running this example app locally

### Prerequisites

Register a new client at the [sgID developer portal](https://developer.id.gov.sg). Feel free to register a test client; there is no limit to the number of clients you can create.

### Steps to run locally

1. Clone this repo.

```
git clone https://github.com/opengovsg/sgid-client-python.git
```

2. Go to this folder and copy the contents of `example.env` into a new file called `.env`.

```
cd sgid-client-python/examples/flask
cat .env.example > .env
```

2. Replace the values in `.env` with the credentials of your sgID client (see [Prerequisites](#prerequisites)).

3. Run:

```
pip install -r requirements.txt
flask run
```

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
rm requirements.txt
poetry export >> requirements.txt
```
