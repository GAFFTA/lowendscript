#!/bin/bash

function check_install {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        executable=$1
        shift
        while [ -n "$1" ]
        do
            DEBIAN_FRONTEND=noninteractive apt-get -q -y install "$1"
            print_info "$1 installed for $executable"
            shift
        done
    else
        print_warn "$2 already installed"
    fi
}

function check_remove {
    if [ -n "`which "$1" 2>/dev/null`" ]
    then
        DEBIAN_FRONTEND=noninteractive apt-get -q -y remove --purge "$2"
        print_info "$2 removed"
    else
        print_warn "$2 is not installed"
    fi
}

function check_sanity {
    # Do some sanity checking.
    if [ $(/usr/bin/id -u) != "0" ]
    then
        die 'Must be run by root user'
    fi

    if [ ! -f /etc/debian_version ]
    then
        die "Distribution is not supported"
    fi
}

function die {
    echo "ERROR: $1" > /dev/null 1>&2
    exit 1
}

function get_domain_name() {
    # Getting rid of the lowest part.
    domain=${1%.*}
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    case "$lowest" in
    com|net|org|gov|edu|co)
        domain=${domain%.*}
        ;;
    esac
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    [ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password() {
    # Check whether our local salt is present.
    SALT=/var/lib/radom_salt
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=`(cat "$SALT"; echo $1) | md5sum | base64`
    echo ${password:0:13}
}

function install_dash {
    check_install dash dash
    rm -f /bin/sh
    ln -s dash /bin/sh
}

function install_dropbear {
    check_install ssh ssh
    check_install dropbear dropbear
    check_install /usr/sbin/xinetd xinetd

    # Disable SSH
    touch /etc/ssh/sshd_not_to_be_run
    invoke-rc.d ssh stop

    if [ -z $SSH_PORT ];then
        SSH_PORT=22
        print_info "Dropbear port set to 22"
    else
        if [ $SSH_PORT -le 65535 ]; then
            print_info "Dropbear port set to $SSH_PORT"
        else
            SSH_PORT=22
            print_warn "Dropbear port changed to 22"
        fi
    fi
    # Enable dropbear to start. We are going to use xinetd as it is just
    # easier to configure and might be used for other things.
    cat > /etc/xinetd.d/dropbear <<END
service dropbear
{
    socket_type     = stream
    only_from       = 0.0.0.0
    wait            = no
    port            = $SSH_PORT
    type            = unlisted
    flags			= ipv4
    user            = root
    protocol        = tcp
    server          = /usr/sbin/dropbear
    server_args     = -i
    disable         = no
}
END
    invoke-rc.d xinetd restart
}

function install_exim4 {
    check_install mail exim4
    if [ -f /etc/exim4/update-exim4.conf.conf ]
    then
        sed -i \
            "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
            /etc/exim4/update-exim4.conf.conf
        invoke-rc.d exim4 restart
    fi
}

function install_mysql {
    # Install the MySQL packages
    check_install mysqld mysql-server
    check_install mysql mysql-client

    # Install a low-end copy of the my.cnf to disable InnoDB, and then delete
    # all the related files.
    invoke-rc.d mysql stop
    rm -f /var/lib/mysql/ib*
    cat > /etc/mysql/conf.d/lowendbox.cnf <<END
[mysqld]
key_buffer = 8M
query_cache_size = 0
skip-innodb
END
    invoke-rc.d mysql start

    # Generating a new password for the root user.
    passwd=`get_password root@mysql`
    mysqladmin password "$passwd"
    cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
    chmod 600 ~/.my.cnf
}

function install_nginx {
    check_install nginx nginx
    
    # Need to increase the bucket size for Debian 5.
    cat > /etc/nginx/conf.d/lowendbox.conf <<END
server_names_hash_bucket_size 64;
END

    invoke-rc.d nginx restart
}

function install_php {
    check_install php-cgi php5-cgi php5-cli php5-mysql
    cat > /etc/init.d/php-cgi <<END
#!/bin/bash
### BEGIN INIT INFO
# Provides:          php-cgi
# Required-Start:    networking
# Required-Stop:     networking
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start the PHP FastCGI processes web server.
### END INIT INFO

PATH=/sbin:/bin:/usr/sbin:/usr/bin
NAME="php-cgi"
DESC="php-cgi"
PIDFILE="/var/run/www/php.pid"
FCGIPROGRAM="/usr/bin/php-cgi"
FCGISOCKET="/var/run/www/php.sock"
FCGIUSER="www-data"
FCGIGROUP="www-data"

if [ -e /etc/default/php-cgi ]
then
    source /etc/default/php-cgi
fi

[ -z "\$PHP_FCGI_CHILDREN" ] && PHP_FCGI_CHILDREN=1
[ -z "\$PHP_FCGI_MAX_REQUESTS" ] && PHP_FCGI_MAX_REQUESTS=5000

ALLOWED_ENV="PATH USER PHP_FCGI_CHILDREN PHP_FCGI_MAX_REQUESTS FCGI_WEB_SERVER_ADDRS"

set -e

. /lib/lsb/init-functions

case "\$1" in
start)
    unset E
    for i in \${ALLOWED_ENV}; do
        E="\${E} \${i}=\${!i}"
    done
    log_daemon_msg "Starting \$DESC" \$NAME
    env - \${E} start-stop-daemon --start -x \$FCGIPROGRAM -p \$PIDFILE \\
        -c \$FCGIUSER:\$FCGIGROUP -b -m -- -b \$FCGISOCKET
    log_end_msg 0
    ;;
stop)
    log_daemon_msg "Stopping \$DESC" \$NAME
    if start-stop-daemon --quiet --stop --oknodo --retry 30 \\
        --pidfile \$PIDFILE --exec \$FCGIPROGRAM
    then
        rm -f \$PIDFILE
        log_end_msg 0
    else
        log_end_msg 1
    fi
    ;;
restart|force-reload)
    \$0 stop
    sleep 1
    \$0 start
    ;;
*)
    echo "Usage: \$0 {start|stop|restart|force-reload}" >&2
    exit 1
    ;;
esac
exit 0
END
    chmod 755 /etc/init.d/php-cgi
    mkdir -p /var/run/www
    chown www-data:www-data /var/run/www

    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php$ {
    include /etc/nginx/fastcgi_params;

    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    if (-f \$request_filename) {
        fastcgi_pass unix:/var/run/www/php.sock;
    }
}
END
    update-rc.d php-cgi defaults
    invoke-rc.d php-cgi start
}

function install_iptables {

    check_install iptables iptables

    if [ -z "$1" ]
    then
        die "Usage: `basename $0` iptables <ssh-port-#>"
    fi

    # Create startup rules
    cat > /etc/init.d/iptables <<END
#! /bin/sh

#This is an Ubuntu adapted iptables script from gentoo
#(http://www.gentoo.org) which was originally distributed
#under the terms of the GNU General Public License v2
#and was Copyrighted 1999-2004 by the Gentoo Foundation
#
#This adapted version was intended for and ad-hoc personal
#situation and as such no warranty is provided.

### BEGIN INIT INFO
# Provides:          iptables
# Required-Start:    \$local_fs \$remote_fs \$network \$syslog
# Required-Stop:     \$local_fs \$remote_fs \$network \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start the iptables firewall
### END INIT INFO

. /lib/lsb/init-functions


IPTABLES_SAVE="/etc/default/iptables-rules"
SAVE_RESTORE_OPTIONS="-c"


checkrules() {
    if [ ! -f \${IPTABLES_SAVE} ]
    then
        echo "Not starting iptables. First create some rules then run"
        echo "\"/etc/init.d/iptables save\""
        return 1
    fi
}

save() {
    /sbin/iptables-save \${SAVE_RESTORE_OPTIONS} > \${IPTABLES_SAVE}
    return \$?
}

start(){
    checkrules || return 1
    /sbin/iptables-restore \${SAVE_RESTORE_OPTIONS} < \${IPTABLES_SAVE}
    return \$?
}


case "\$1" in
    save)
        echo -n "Saving iptables state..."
        save
        if [ \$? -eq 0 ] ; then
            echo " ok"
        else
            echo " error !"
        fi
    ;;

    start)
        log_begin_msg "Loading iptables state and starting firewall..."
        start
        log_end_msg \$?
    ;;
    stop)
        log_begin_msg "Stopping firewall..."
        for a in \`cat /proc/net/ip_tables_names\`; do
            /sbin/iptables -F -t \$a
            /sbin/iptables -X -t \$a

            if [ \$a == nat ]; then
                /sbin/iptables -t nat -P PREROUTING ACCEPT
                /sbin/iptables -t nat -P POSTROUTING ACCEPT
                /sbin/iptables -t nat -P OUTPUT ACCEPT
            elif [ \$a == mangle ]; then
                /sbin/iptables -t mangle -P PREROUTING ACCEPT
                /sbin/iptables -t mangle -P INPUT ACCEPT
                /sbin/iptables -t mangle -P FORWARD ACCEPT
                /sbin/iptables -t mangle -P OUTPUT ACCEPT
                /sbin/iptables -t mangle -P POSTROUTING ACCEPT
            elif [ \$a == filter ]; then
                /sbin/iptables -t filter -P INPUT ACCEPT
                /sbin/iptables -t filter -P FORWARD ACCEPT
                /sbin/iptables -t filter -P OUTPUT ACCEPT
            fi
        done
        log_end_msg 0
    ;;

    restart)
        log_begin_msg "Restarting firewall..."
        for a in \`cat /proc/net/ip_tables_names\`; do
            /sbin/iptables -F -t \$a
            /sbin/iptables -X -t \$a
        done;
        start
        log_end_msg \$?
    ;;

    *)
        echo "Usage: /etc/init.d/iptables {start|stop|restart|save}" >&2
        exit 1
        ;;
esac

exit 0
END
    chmod +x /etc/init.d/iptables

    # Flush any existing iptables
    /sbin/iptables -v -F

    # http://articles.slicehost.com/2010/4/30/ubuntu-lucid-setup-part-1

    #  Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
    /sbin/iptables -v -A INPUT -i lo -j ACCEPT
    /sbin/iptables -v -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

    #  Accepts all established inbound connections
    /sbin/iptables -v -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    #  Allows all outbound traffic
    #  You can modify this to only allow certain traffic
    /sbin/iptables -v -A OUTPUT -j ACCEPT

    # Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
    /sbin/iptables -v -A INPUT -p tcp --dport 80 -j ACCEPT
    /sbin/iptables -v -A INPUT -p tcp --dport 443 -j ACCEPT

    # IF YOU USE INCOMMING MAIL UN-COMMENT THESE!!!

    # Allows POP (and SSL-POP)
    #/sbin/iptables -v -A INPUT -p tcp --dport 110 -j ACCEPT
    #/sbin/iptables -v -A INPUT -p tcp --dport 995 -j ACCEPT

    # SMTP (and SSMTP)
    #/sbin/iptables -v -A INPUT -p tcp --dport 25 -j ACCEPT
    #/sbin/iptables -v -A INPUT -p tcp --dport 465 -j ACCEPT

    # IMAP (and IMAPS)
    #/sbin/iptables -v -A INPUT -p tcp --dport 143 -j ACCEPT
    #/sbin/iptables -v -A INPUT -p tcp --dport 993 -j ACCEPT

    #  Allows SSH connections (only 3 attempts by an IP every 2 minutes, drop the rest to prevent SSH attacks)
    /sbin/iptables -v -A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --set --name DEFAULT --rsource
    /sbin/iptables -v -A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --update --seconds 120 --hitcount 3 --name DEFAULT --rsource -j DROP
    /sbin/iptables -v -A INPUT -p tcp -m state --state NEW --dport $1 -j ACCEPT

    # Allow ping
    /sbin/iptables -v -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

    # log iptables denied calls
    /sbin/iptables -v -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

    # Reject all other inbound - default deny unless explicitly allowed policy
    /sbin/iptables -v -A INPUT -j REJECT
    /sbin/iptables -v -A FORWARD -j REJECT

    /etc/init.d/iptables save
    update-rc.d iptables defaults
}

function install_syslogd {
    # We just need a simple vanilla syslogd. Also there is no need to log to
    # so many files (waste of fd). Just dump them into
    # /var/log/(cron/mail/messages)
    check_install /usr/sbin/syslogd inetutils-syslogd
    invoke-rc.d inetutils-syslogd stop

    for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
    do
        [ -f "$file" ] && rm -f "$file"
    done
    for dir in fsck news
    do
        [ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
    done

    cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none -/var/log/messages
cron.*                  -/var/log/cron
mail.*                  -/var/log/mail
END

    [ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
   rotate 4
   weekly
   missingok
   notifempty
   compress
   sharedscripts
   postrotate
      /etc/init.d/inetutils-syslogd reload >/dev/null
   endscript
}
END

    invoke-rc.d inetutils-syslogd start
}

function install_wordpress {
    check_install wget wget
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

    # Downloading the WordPress' latest and greatest distribution.
    mkdir /tmp/wordpress.$$
    wget -O - http://wordpress.org/latest.tar.gz | \
        tar zxf - -C /tmp/wordpress.$$
    mv /tmp/wordpress.$$/wordpress "/var/www/$1"
    rm -rf /tmp/wordpress.$$
    chown root:root -R "/var/www/$1"

    # Setting up the MySQL database
    dbname=`echo $1 | tr . _`
    userid=`get_domain_name $1`
    # MySQL userid cannot be more than 15 characters long
    userid="${userid:0:15}"
    passwd=`get_password "$userid@mysql"`
    cp "/var/www/$1/wp-config-sample.php" "/var/www/$1/wp-config.php"
    sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
        "/var/www/$1/wp-config.php"
    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql

    # Setting up Nginx mapping
    cat > "/etc/nginx/sites-enabled/$1.conf" <<END
server {
    server_name $1;
    root /var/www/$1;
    include /etc/nginx/fastcgi_php;
    location / {
        index index.php;
        if (!-e \$request_filename) {
            rewrite ^(.*)$  /index.php last;
        }
    }
}
END
    invoke-rc.d nginx reload
}

function print_info {
    echo -n -e '\e[1;36m'
    echo -n $1
    echo -e '\e[0m'
}

function print_warn {
    echo -n -e '\e[1;33m'
    echo -n $1
    echo -e '\e[0m'
}

function remove_unneeded {
    # Some Debian have portmap installed. We don't need that.
    check_remove /sbin/portmap portmap

    # Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
    # which might make some low-end VPS inoperatable. We will do this even
    # before running apt-get update.
    check_remove /usr/sbin/rsyslogd rsyslog

    # Other packages that seem to be pretty common in standard OpenVZ
    # templates.
    check_remove /usr/sbin/apache2 'apache2*'
    check_remove /usr/sbin/named bind9
    check_remove /usr/sbin/smbd 'samba*'
    check_remove /usr/sbin/nscd nscd

    # Need to stop sendmail as removing the package does not seem to stop it.
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        invoke-rc.d sendmail stop
        check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
    fi
}

function update_upgrade {
    # Run through the apt-get update/upgrade first. This should be done before
    # we try to install any package
    apt-get -q -y update
	check_install locales locales
    dpkg-reconfigure locales
    apt-get -q -y upgrade
}

function vzquota_fix {
     if [ -f /etc/init.d/vzquota -a ! -e /etc/insserv/overrides/vzquota ]; then
cat > /etc/insserv/overrides/vzquota <<END
### BEGIN INIT INFO
# Provides: vzquota
# Required-Start: \$all
# Required-Stop: \$all
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start vzquota at the end of boot
# Description: This command is used to configure and see disk quota statistics for Containers.
### END INIT INFO
END
        print_info "/etc/insserv/overrides/vzquota created"
    else
        print_warn "/etc/insserv/overrides/vzquota not created"
    fi
    if [ -f /etc/rc6.d/K00vzreboot ];then
        rm /etc/rc6.d/K00vzreboot
        print_info "/etc/rc6.d/K00vzreboot removed"
    fi
    if [ -f /etc/rc6.d/S00vzreboot ];then
        rm /etc/rc6.d/S00vzreboot
        print_info "/etc/rc6.d/S00vzreboot removed"
    fi
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

[ -r ./setup-debian.conf ] && . ./setup-debian.conf
check_sanity
case "$1" in
exim4)
    install_exim4
    ;;
iptables)
    install_iptables $SSH_PORT
    ;;
mysql)
    install_mysql
    ;;
nginx)
    install_nginx
    ;;
php)
    install_php
    ;;
vzquota)
    vzquota_fix
    ;;
system)
    remove_unneeded
    update_upgrade
	check_install tzdata tzdata
    dpkg-reconfigure tzdata
    install_dash
    install_syslogd
    install_dropbear
    passwd
    ;;
wordpress)
    install_wordpress $2
    ;;
*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in vzquota system exim4 iptables mysql nginx php wordpress
    do
        echo '  -' $option
    done
    ;;
esac
