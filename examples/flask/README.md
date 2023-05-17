# Flask example sgID app

The example application code is in `app.py`. You can copy this code to bootstrap your sgID client application, and run this app locally to understand how this SDK helps you interact with the sgID server.

## Running this example app locally

### Prerequisites

**Register a new sgID client**

1. Go to the [sgID developer portal](https://developer.id.gov.sg) and log in using sgID. Click "Register new client".
2. Enter a test name and description (there is no limit to the number of clients you can create).
3. Under "Scopes", add "NAME".
4. Under "Callback URLs", add the following:

```
http://localhost:2000/api/callback
```

5. Click "Register" to save the client and download the credentials.

### Running the app

1. Clone this repo.

```
git clone https://github.com/opengovsg/sgid-client-python.git
```

2. Go to this folder (`examples/flask`) and copy the contents of `example.env` into a new file called `.env`.

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
poetry export > requirements.txt
```
