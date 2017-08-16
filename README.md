# api.kellenschmidt.com
[![Build Status](https://travis-ci.org/kellenschmidt/api.kellenschmidt.com.svg?branch=master)](https://travis-ci.org/kellenschmidt/api.kellenschmidt.com)
[![Stories in Ready](https://badge.waffle.io/kellenschmidt/api.kellenschmidt.com.svg?label=ready&title=Ready)](http://waffle.io/kellenschmidt/api.kellenschmidt.com)
[![Stories in Progress](https://badge.waffle.io/kellenschmidt/api.kellenschmidt.com.svg?label=In%20Progress&title=In%20Progress)](http://waffle.io/kellenschmidt/api.kellenschmidt.com)

RESTful API enabling database integration with the kellenschmidt.com suite of websites and applications.

Accessed at [api.kellenschmidt.com](api.kellenschmidt.com)

Documentation at [docs.kellensurlshortener.apiary.io](http://docs.kellensurlshortener.apiary.io)

## Tools Used
[Slim Framework](https://www.slimframework.com/) for the API to interact with the database

[Apiary](https://piary.io/) to document the API

[MySQL](https://mysql.com) database to store the data

## Usage

### Portfolio Website
Accesses database to:
- Expose content for modals
- Log information about page visitors

https://kellenschmidt.com

### URL Shortener in Angular 2
Access database to preform these actions:
- Get, create, update and hide short links
- Get data to redirect short links
- Count clicks on short links
- Register and log in users
- Authenticate http requests
- Track data about all interactions
- Log information about page visitors

https://urlshortener.kellenschmidt.com
