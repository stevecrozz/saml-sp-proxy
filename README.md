# SAML 2.0 Service Provider and Reverse Proxy

~~~bash
docker run --rm -it \
  -v /path/to/data:/data stevecrozz/saml-sp-proxy \
  -idp-metadata /data/idp-metadata.xml \
  -service-certificate /data/cert \
  -service-key /data/key \
  -service-root-url "https://myurl.com" \
  -target "http://underlying-service"
~~~

Since crewjam/saml/samlsp requires a set of SP keys (see
https://github.com/crewjam/saml/issues/149), you'll need a pair even if you
don't use them. You can create them like this:

~~~bash
openssl req -x509 \
  -newkey rsa:2048 \
  -keyout key \
  -out cert \
  -days 365 \
  -nodes -subj "/CN=myservice.example.com"
~~~

Copied from https://github.com/dustin-decker/saml-proxy and modified from
there. Thanks to @dustin-decker for the working starting point.
