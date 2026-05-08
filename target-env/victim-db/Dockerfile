FROM mysql:8.0
LABEL description="Victim database — MySQL with weak credentials for lab"

ENV MYSQL_ROOT_PASSWORD=root
ENV MYSQL_DATABASE=labdb
ENV MYSQL_USER=admin
ENV MYSQL_PASSWORD=password123

COPY seed.sql /docker-entrypoint-initdb.d/seed.sql

EXPOSE 3306
