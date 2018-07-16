# slimphp-api

[![CircleCI](https://circleci.com/gh/kellenschmidt/slimphp-api.svg?style=svg)](https://circleci.com/gh/kellenschmidt/slimphp-api)

RESTful API enabling database integration with the kellenschmidt.com suite of websites and applications.

Accessed at [kellenschmidt.com/api/v1](https://kellenschmidt.com/api/v1)

Documentation at [kspw.docs.apiary.io/](https://kspw.docs.apiary.io)

## Tools Used

[Slim Framework](https://www.slimframework.com/) for the API to interact with the database

[Apiary](https://apiary.io/) to document the API

[MySQL](https://mysql.com) database to store the data

## Usage

### Interactive Resume Portfolio Website

Accesses database to:

- Expose content for
  - Projects cards and modals
  - Work experience cards and modals
  - Skills chips
  - Courses carousel
- Log information about page visitors

https://kellenschmidt.com

### URL Shortener in Angular

Access database to preform these actions:

- Get, create, update and hide short links
- Get data to redirect short links
- Count clicks on short links
- Register and log in users
- Authenticate http requests
- Track data about all interactions
- Log information about page visitors

https://kellenschmidt.com/url

## Local development

### With Docker

Must have mysql database running. Must create `slimphp-api.env` with `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_DATABASE`, `MYSQL_PASSWORD`, and `JWT_SECRET` defined

```sh
docker build -t kellenschmidt/slimphp-api .
docker run --env-file ./slimphp-api.env -p 8080:80 -d kellenschmidt/slimphp-api
```

Access at `localhost:8080`

### Without Docker

Must have mysql database running. Verify database connection settings in `/src/settings.php` before running.

```Shell
git clone https://github.com/kellenschmidt/api.kellenschmidt.com.git
cd api.kellenschmidt.com
sh install_composer.sh
php composer.phar install
php composer.phar start
```

Access at `localhost:8080`
