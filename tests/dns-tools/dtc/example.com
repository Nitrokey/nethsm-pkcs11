example.com.	86400	IN	SOA	ns1.example.com. hostmaster.example.com. 2019052103 10800 15 604800 10800
example.com.	86400	IN	NS	ns1.example.com.
example.com.	86400	IN	MX	10 localhost.
ftp.example.com.	86400	IN	CNAME	www.example.com.
ns1.example.com.	86400	IN	A	127.0.0.1
www.example.com.	86400	IN	A	127.0.0.2
yo.example.com.	86400	IN	A	127.0.0.3
