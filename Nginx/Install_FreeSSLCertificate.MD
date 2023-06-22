1.  Download the Let’s Encrypt Client
    First, download the Let’s Encrypt client, certbot.
    As mentioned just above, we tested the instructions on Ubuntu 16.04, and these are the appropriate commands on that platform:

    $ apt-get update
    $ sudo apt-get install certbot
    $ apt-get install python-certbot-nginx

    With Ubuntu 18.04 and later, substitute the Python 3 version:
    $ apt-get update
    $ sudo apt-get install certbot
    $ apt-get install python3-certbot-nginx

2.  Set Up NGINX
    certbot can automatically configure NGINX for SSL/TLS. It looks for and modifies the server block in your NGINX configuration that contains a server_name directive with the domain name you’re requesting a certificate for. In our example, the domain is www.example.com.
    Assuming you’re starting with a fresh NGINX install, use a text editor to create a file in the /etc/nginx/conf.d directory named domain‑name.conf (so in our example, www.example.com.conf).

    Specify your domain name (and variants, if any) with the server_name directive:

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
        server_name example.com www.example.com;
    }

    Save the file, then run this command to verify the syntax of your configuration and restart NGINX:

    $ nginx -t && nginx -s reload