FROM mcr.microsoft.com/mssql/server:2022-latest

COPY entrypoint.sh /entrypoint.sh
COPY init /docker-entrypoint-initdb.d

USER root
RUN chmod +x /entrypoint.sh
USER mssql

ENTRYPOINT ["/entrypoint.sh"]
