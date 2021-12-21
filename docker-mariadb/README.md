This is the folder to get the required mariadb up and running in a local environment.

# How to start with the mariadb as docker-image
* Install Docker Desktop
* Open Cmd-Line tool (Powershell on windows)
* Navigate to this directory
* Build the image
    `docker build . --tag oauth-database`
* Start the image with the docker-compose
    `docker-compose up -d`
* To see if its running type `docker container ls`
* To see the logs of the container type `docker container lobs oauth-db`
* Stop the image with `docker-compose down`

MariaDB is now accessible on `localhost:3306`
