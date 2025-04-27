# Sample Application with PHP

This sample is running on: https://php.is-easy-on-scalingo.com/

## Detection of the application type

Your project MUST contain an `index.php` file at the root of your
project. Nothing else is required.

## Deploy via Git

Create an application on https://scalingo.com, then:

```shell
scalingo --app my-app git-setup
git push scalingo master
```

And that's it!

## Deploy via One-Click

[![Deploy to Scalingo](https://cdn.scalingo.com/deploy/button.svg)](https://dashboard.scalingo.com/create/app?source=https://github.com/kuisa/scalingo-php#master)

## Running Locally

```shell
docker compose up
```

The app listens by default on the port 8080 or the one defined in the `PORT`
environment variable.
