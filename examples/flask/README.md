# Flask example sgID app

The example application code is in `app.py`. You can copy this code to bootstrap your sgID client application.

## Running locally

1. Register a new client at the [sgID developer portal](https://developer.id.gov.sg). Feel free to register a test client; there is no limit to the number of clients you can create.
2. Create a new file called `.env` in this directory. Copy the contents of `.env.example` into this new file, and replace the values with the credentials of the client created in step 1.
3. Run:

```
pip install -r requirements.txt
flask run
```

## Development

To start the server in debug mode, run:

```
flask run --debug
```

## Adding dependencies

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
