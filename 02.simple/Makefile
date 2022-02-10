all: HTTPSimple.c
	gcc -o HTTPSimple HTTPSimple.c 

clean:
	rm -rf HTTPSimple

install: HTTPSimple
	useradd -c "HTTPSimple user" -r -s /sbin/nologin -d /var/www/simpleweb httpsimple
	install -o root -g root -m 0755 HTTPSimple /usr/local/sbin/                       
	install -o root -g root -m 0644 httpsimple.service /etc/systemd/system/           
	systemctl daemon-reload                                                           
	systemctl restart httpsimple.service
	mkdir -p /var/www/simpleweb
	cp -r webroot -t /var/www/simpleweb/
	chown -R httpsimple:httpsimple /var/www/simpleweb

uninstall:
	systemctl stop httpsimple
	rm -rf /var/www/simpleweb
	rm -f /usr/local/sbin/HTTPSimple
	rm -f /etc/systemd/system/httpsimple.service
	systemctl daemon-reload
	userdel -f httpsimple
