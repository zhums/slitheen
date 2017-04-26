#!/bin/bash

./phantomjs --ssl-callbacks=slitheen --ssl-protocol=tlsv1.2 --ssl-ciphers=ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384 ous.js > ous.out
