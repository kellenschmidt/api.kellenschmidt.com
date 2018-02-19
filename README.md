# api.kellenschmidt.com

RESTful API enabling database integration with the kellenschmidt.com suite of websites and applications.

Accessed at [api.kellenschmidt.com](http://api.kellenschmidt.com)

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

http://kellenschmidt.com

### URL Shortener in Angular

Access database to preform these actions:

- Get, create, update and hide short links
- Get data to redirect short links
- Count clicks on short links
- Register and log in users
- Authenticate http requests
- Track data about all interactions
- Log information about page visitors

http://kellenschmidt.com/url

## Local development

Must have MySQL database running. Verify database connection settings in `/src/settings.php` before running.

```Shell
git clone https://github.com/kellenschmidt/api.kellenschmidt.com.git
cd api.kellenschmidt.com
sh install_composer.sh
php composer.phar install
php composer.phar start
```

Visit `localhost:8080`
