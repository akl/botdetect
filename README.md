Botdetect
===

botdetect is a small program that reads IPs on STDIN in the form IP1|IP2 and calculates which IP 
produces too many requests where the ratio between HTML requests an asset requests (images, CSS, Javascript, fonts)
leans too far in favour of HTML.

Assuming that bad bots usually don't load assets, this is a relatively straight-forward way of detecting bad bots.

Please note that this is only a starting point for a bot blocker that you can use in production. You will at least need to add a way to whitelist IPs, hostnames or entire networks. Otherwise the program will block everything that exceeds the limits, including good bots like Google or Bing or any IPs that you need to be able to access your website.

Integration into Apache
------------------------

botdetect can be easily integrated into the apache webserver through mod_rewrite's 


```
LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so

RewriteEngine on
RewriteMap blmap prg:/usr/local/bin/botdetect

RewriteCond %{REQUEST_URI} !.html
RewriteCond ${blmap:%{REMOTE_ADDR}|%{HTTP:X-FORWARDED-FOR}} =BLOCK
RewriteRule (.*) "-" [F]
```

In case you want to change the default parameters create a wrapper script and call botdetect from there with 
all the parameters you might want to set.


Usage
-----

```
botdetect [options]

  -ignore-private-ips=true: igore private IPs when building the checksum
  -interval=5s: build a new blacklist after this much time
  -max-ratio=0.85: blacklist IPs if the app/assets ratio is above this threshold
  -max-requests=30: maximum number of requests to allow
  -timeout=10ms: wait this long for a redis response
  -timeslot=1m0s: the duration to use to group requests
  -timestamp-format="15:04": the key by which to group requests (golang time format, default: hour:minute)
  -trace=false: trace the decisions the program makes
  -version=false: Show the program version
  -window=1h0m0s: the time window to observe
```

