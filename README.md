<img src="https://ownpush.com/wp-content/uploads/2016/02/ownpush_128-logoSpelledout.png">
### _Next generation, open-source push services for Android_ ###

# __OwnPush Push Services__


This is the push provider webapp which makes up 1/2 of the OwnPush push service. The service that is contained within this repo provides the device websocket connections **ONLY** - all application management and user
interactions through the web-ui will be done on the seperate management webapp which makes up the 2nd half of the service.


## __Key Points__

* Based on websockets (multiple example implementations / libs available)
* Initial support on Android platform with scope to expand to IoT later
* Public / Private key encrypttion used to protect push messages (NaCl)
* Handshake and messages to and from the client device are JWT formatted and B64 encoded
* Messages sent from the deveoper to the push service is in JWT format and B64 encoded
* Messages from the developer are signed via NaCl
* Uses sqlite 


## __config.ini__

Example config :

```
[redisinfo]
host = 172.17.0.2
port = 6379

[serversettings]
debug = false
timeout = 900
delay = 600
secret = change_me
```

* Normally you would only need to update the redis host IP address

## __Docker Deploy__

1. Clone this server repo
3. Build the custom redis container
```
$ docker build -t push_redis_server redis_conf
```
4. Start the new redis server
```
$ docker run --name push-redis -d push_redis_server
```
5. Create your config.ini (see above)
6. Build the OwnPush container
```
$ docker build -t ownpush_server .
```
7. Start and link the OwnPush container to the 2 other services
```
$ docker run --name ownpush_t --link push-redis --link push-sql -d ownpush_server
```

## __Normal Deploy__

1. Clone this server repo
3. Build the custom redis container
```
$ docker build -t push_redis_server redis_conf
```
4. Start the new redis server
```
$ docker run --name push-redis -d push_redis_server
```
5. Create your config.ini (see above)
6. Setup python environment (using virtualenv below)
```
$ virtualenv venv
$ ./venv/bin/pip install -r requirements.txt
```
7. Start the server
```
$ ./venv/bin/gunicorn -k tornado server
```

## __First Run__

The first run will generate your server / application keys both for the webapp-to-push server signing, and server-to-device encryption (an example is shown below)

```
PRIVATE API / SIGN KEY (KEEP SAFE)
8a927cf5737ac7e74d56305605a3a8bada04aadc706714fefacef9e7dcb6eb92



PRIVATE APP / ENCRYPT (KEEP SAFE)
11ea418004a6d49a025ea0168c66742b9fecf34db6962a7d26bb3a3e5fa1c136
PUBLIC APP / ENCRYPT (ADD TO APP)
dccf6c720043c830810dc656d61d8504a4cc10a774d4db5bdc91b78b285bd74c
```

### PRIVATE API / SIGN KEY
Will be added to your web service app that will be the starting point for the push messaging (See demo web apps provided)


### PRIVATE APP / ENCRYPT (KEEP SAFE)
Will be added to your Android app manifest for permission and to the push resistration interaction (See demo Android apps provided)


## __Other Links__

### Demo WebApp / Server Apps
https://github.com/ownpush/otp_demo_server

https://github.com/ownpush/rss_demo_server

### Demo Android APPS
https://github.com/ownpush/android_app_otp_demo

https://github.com/ownpush/android_app_rss_demo

## Other Documentation
https://github.com/ownpush/docs







