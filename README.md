# ripe-atlas-shrugd
Fake DNS resolver check using RIPE Atlas

## To start

You'll need the RIPE Atlas library:

```
$ pip3 install --user ripe.atlas.cousteau      # for creating measurements
```

You'll also probably need either the IANA root or the Yeti root:

```
$ wget -O iana-root.txt ftp://rs.internic.net/domain/named.root 
$ wget -O yeti-root.txt https://raw.githubusercontent.com/BII-Lab/Yeti-Project/master/domain/named.cache
```

You can start a measurement against one of these:

```
$ python3 shrugd-create.py iana-root.txt
```
