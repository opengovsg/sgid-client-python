# Flask example sgID app

The example application code is in `app.py`. You can copy this code to bootstrap your sgID client application, and run this app locally to understand how this SDK helps you interact with the sgID server.

## Running this example app locally

Refer to sgID's [documentation](https://docs.id.gov.sg/integrations-with-sgid/python/framework-guides/flask-with-single-page-app-frontend) for a detailed guide on what this example does and how to run it locally.

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
