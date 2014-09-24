FROM debian:unstable
# MAINTAINER Plastic-Data Team <info@plastic-data.org>
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y git python-babel python-bleach python-bson python-bson-ext python-isodate python-pastedeploy python-pip python-pymongo python-pymongo-ext python-tz python-weberror python-webob python-ws4py python-zmq
RUN apt-get clean
RUN pip install -e git+https://github.com/etalab/biryani.git@biryani1#egg=Biryani1
RUN pip install -e git+https://github.com/plastic-data/suq1.git#egg=Suq1
RUN pip install -e git+https://github.com/plastic-data/plastic-auth-api.git#egg=Plastic-Auth-API

RUN DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y python-gevent
RUN pip install chaussette
COPY production.ini /src/plastic-auth-api/production.ini
COPY serve_plastic_auth_api.sh /src/plastic-auth-api/serve_plastic_auth_api.sh
CMD /src/plastic-auth-api/serve_plastic_auth_api.sh
EXPOSE 2040
