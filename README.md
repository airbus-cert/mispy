# python-misp


[![Documentation built](https://readthedocs.org/projects/python-misp/badge/?version=latest)](http://python-misp.readthedocs.org/en/latest/?badge=latest)
[![Continuous integration](https://travis-ci.org/nbareil/python-misp.svg?branch=master)](https://travis-ci.org/nbareil/python-misp)

A pythonic MISP module.

[API Documentation](https://python-misp.readthedocs.io/en/latest/)
and unit-tests are available.

## Examples

Get attributes and tags from an event:
```python
server = MispServer(url=URL, apikey=APIKEY)
event = server.events.get(42)
for attr in event.attributes:
    print("%s %s %s" % (attr.category, attr.type, attr.value))
    if attr.type == 'malware-sample':
        server.download(attr)
for tag in event.tags:
    print("%s" % tag.name)
```

Add a new attribute to an event
```python
server = MispServer(url=URL, apikey=APIKEY)
event = server.events.get(42)
new_attr = MispAttribute()
new_attr.value = "127.0.0.1"
new_attr.category = "Network activity"
new_attr.type = "ip-dst"
new_attr.comment = "Dope IOC"
new_attr.to_ids = True
event.attributes.add(new_attr)
server.events.update(event)
```

Search for an attribute
```python
server = MispServer(url=URL, apikey=APIKEY)
events = server.attributes.search(value="087bffa8a570079948310dc9731c5709")
for event in events:
    print("%i - %s" % (event.id, event.info))
```

## Credits

Airbus Group CERT
