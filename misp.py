#! /usr/bin/env python

import unittest
import xml.etree.ElementTree as ET
import lxml
from lxml import objectify
import time
import datetime
import requests
import os

DEFAULT_MISP_URL = 'https://misp.internal'
DEFAULT_ORG = 'ACME Corp.'
DEFAULT_ORGC = DEFAULT_ORG
MISP_API_KEY = open(os.path.join(os.environ['HOME'], '.misp_api_key')).read()
MISP_SSL_CHAIN = '/etc/ssl/certs/ca-certificates.crt'

# To remove this deprecation warning:
# SecurityWarning: Certificate has no `subjectAltName`, falling back to check
# for a `commonName` for now. This feature is being removed by major browsers
# and deprecated by RFC 2818. (See https://github.com/shazow/urllib3/issues/497
# for details.)
requests.packages.urllib3.disable_warnings()

class MispBaseObject(object):
    def __init__(self):
        self._uuid = None
        self._timestamp = None
        self._comment = None
        self._distribution = None
        self._threat_level_id = None
        self._analysis = None

    def to_xml(self):
        obj = self.to_xml_object()
        lxml.objectify.deannotate(obj, xsi_nil=True)
        lxml.etree.cleanup_namespaces(obj)
        return lxml.etree.tostring(obj)

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = value

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self):
        self._comment = value

    @property
    def timestamp(self):
        if self._timestamp:
            return self._timestamp
        return int(time.time())

    @timestamp.setter
    def timestamp(self, value):
        val = None
        if type(value) is int or type(value) is objectify.IntElement:
            val = int(value)
        elif type(value) is datetime.datetime:
            val = int(time.mktime(value.timetuple()))
        else:
            raise ValueError('Invalid date type: %s' % type(value))
        self._timestamp = val

    @property
    def distribution(self):
        return self._distribution or 0

    @distribution.setter
    def distribution(self, value):
        if int(value) not in [0, 1, 2, 3]:
            raise ValueError('Invalid distribution value for an attribute')
        self._distribution = value

    @property
    def threat_level_id(self):
        return self._threat_level_id or 0

    @threat_level_id.setter
    def threat_level_id(self, value):
        if int(value) not in [0, 1, 2, 3, 4]:
            raise ValueError('Invalid threat_level_id value for an attribute')
        self._threat_level_id = value

    @property
    def analysis(self):
        return self._analysis

    @analysis.setter
    def analysis(self, value):
        if value and int(value) not in [0, 1, 2]:
            raise ValueError('Invalid analysis value for an attribute')
        self._analysis = value or 0


class MispEvent(MispBaseObject):
    def __init__(self):
        super(MispEvent, self).__init__()
        self._id = None
        self._info = None
        self._org = None
        self._orgc = None
        self._publish = None
        self._proposal_email_lock = None
        self._locked = None
        self._date = None
        self._publish_timestamp = None
        self._published = None
        self._attributes = []

    @property
    def attribute_count(self):
        return len(self.attributes)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if value:
            self._id = int(value)

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, value):
        self._info = str(value)

    @property
    def orgc(self):
        return self._orgc

    @orgc.setter
    def orgc(self, value):
        self._orgc = value

    @property
    def published(self):
        return self._published or 0

    @published.setter
    def published(self, value):
        self._published = value

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, value):
        self._attributes = value

    @property
    def locked(self):
        return self._locked or 0

    @locked.setter
    def locked(self, value):
        self._locked = value

    @property
    def proposal_email_lock(self):
        return self._proposal_email_lock or 0

    @proposal_email_lock.setter
    def proposal_email_lock(self, value):
        self._proposal_email_lock = value

    @property
    def org(self):
        return self._org or DEFAULT_ORG

    @org.setter
    def org(self, value):
        self._org = value

    @property
    def date(self):
        if self._date:
            return self._date
        return datetime.datetime.now().strftime('%Y-%m-%d')

    @date.setter
    def date(self, value):
        val = None
        if type(value) is str or type(value) is objectify.StringElement:
            val = value
        elif type(value) is datetime.datetime:
            val = value.strftime('%Y-%m-%d')
        else:
            raise ValueError('Invalid date type: %s' % type(value))
        self._date = val

    @property
    def publish_timestamp(self):
        if self._publish_timestamp:
            return self._publish_timestamp
        return int(time.time())

    @publish_timestamp.setter
    def publish_timestamp(self, value):
        val = None
        if type(value) is int or  type(value) is objectify.IntElement:
            val = value
        elif type(value) is datetime.datetime:
            val = int(time.mktime(value.timetuple()))
        self._publish_timestamp = val

    @staticmethod
    def from_xml(s):
        event = objectify.fromstring(s)
        return MispEvent.from_xml_object(event)

    @staticmethod
    def from_xml_object(obj):
        if obj.tag.lower() != 'event':
            raise ValueError('Invalid Event XML')
        event = MispEvent()
        for field in ['uuid', 'distribution', 'threat_level_id', 'org',
                      'orgc', 'date', 'info', 'published', 'analysis',
                      'timestamp', 'distribution', 'proposal_email_lock',
                      'locked', 'publish_timestamp', 'id']:
            val = getattr(obj, field)
            setattr(event, field, val)
        #for attr in self.attributes:
        #    event.append(attr.to_xml_object())
        return event

    def to_xml_object(self):
        event = objectify.Element('event')
        for field in ['uuid', 'distribution', 'threat_level_id', 'org',
                      'orgc', 'date', 'info', 'published', 'analysis',
                      'timestamp', 'distribution', 'proposal_email_lock',
                      'locked', 'publish_timestamp', 'id']:
            val = getattr(self, field)
            setattr(event, field, val)
        for attr in self.attributes:
            event.append(attr.to_xml_object())
        return event


class MispTransportError(Exception):
    pass


class MispServer(object):
    def __init__(self):
        self.url = DEFAULT_MISP_URL
        self.headers = {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml',
            'Authorization': MISP_API_KEY
        }
        self.events = MispServer.Events(self)

    def _absolute_url(self, path):
        return self.url + path

    def POST(self, path, body):
        url = self._absolute_url(path)
        requests.post(url, body, headers=self.headers, verify=True)

    def GET(self, path):
        url = self._absolute_url(path)
        resp = requests.get(url, headers=self.headers, verify=MISP_SSL_CHAIN)
        if resp.status_code != 200:
            raise MispTransportError('GET %s: returned status=%d', path, resp.status_code)
        return resp.content

    class Events(object):
        def __init__(self, server):
            self.server = server

        def get(self, evtid):
            raw_evt = self.server.GET('/events/%d' % evtid)
            response = objectify.fromstring(raw_evt)
            return MispEvent.from_xml_object(response.Event)


attr_categories = ['Internal reference', 'Targeting data', 'Antivirus detection',
           'Payload delivery', 'Payload installation', 'Artifacts dropped',
           'Persistence mechanism', 'Network activity', 'Payload type',
           'Attribution', 'External analysis', 'Other']

attr_types = ['md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha1',
         'filename|sha256', 'ip-src', 'ip-dst', 'hostname', 'domain', 'url',
         'user-agent', 'http-method', 'regkey', 'regkey|value', 'AS', 'snort',
         'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'named pipe',
         'mutex', 'vulnerability', 'attachment', 'malware-sample', 'link', 'comment',
         'text', 'email-src', 'email-dst', 'email-subject', 'email-attachment',
         'yara', 'target-user', 'target-email', 'target-machine', 'target-org',
         'target-location', 'target-external', 'other']

class MispAttribute(MispBaseObject):
    def __init__(self):
        super(MispAttribute, self).__init__()
        self._value = None
        self._category = None
        self._type = None
        self._comment = None
        self._to_ids = None
        self._shadowattribute = None

    @property
    def comment(self):
        return self._comment or ''

    @comment.setter
    def comment(self, value):
        self._comment = value

    @property
    def value(self):
        return self._value

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, value):
        if value not in attr_categories:
            raise ValueError('Invalid category for an attribute')
        self._category = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if value not in attr_types:
            raise ValueError('Invalid type for an attribute')
        self._type = value

    @property
    def to_ids(self):
        return self._to_ids

    @to_ids.setter
    def to_ids(self, value):
        self._to_ids = value


class MispEventTest(unittest.TestCase):
    def test_good_xml(self):
        s = r'''<Event>
    <id>42</id>
    <org>ACME and bro.</org>
    <date>2015-10-20</date>
    <threat_level_id>3</threat_level_id>
    <info>AGNOSTIC PANDA</info>
    <published>1</published>
    <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
    <attribute_count>8</attribute_count>
    <analysis>2</analysis>
    <timestamp>1445434988</timestamp>
    <distribution>1</distribution>
    <proposal_email_lock>0</proposal_email_lock>
    <orgc>ACME Corporation</orgc>
    <locked>0</locked>
    <publish_timestamp>1445435155</publish_timestamp>
    </Event>
'''
        m = MispEvent.from_xml(s)
        self.assertEquals(m.uuid, '56278fd8-f2c0-4907-bcca-594e0a3ac101')
        self.assertEquals(m.id, 42)
        self.assertEquals(m.org, 'ACME and bro.')
        self.assertEquals(m.date, '2015-10-20')
        self.assertEquals(m.threat_level_id, 3)
        self.assertEquals(m.info, 'AGNOSTIC PANDA')
        self.assertEquals(m.published, 1)
        self.assertEquals(m.analysis, 2)
        self.assertEquals(m.timestamp, 1445434988)
        self.assertEquals(m.distribution, 1)
        self.assertEquals(m.orgc, 'ACME Corporation')
        self.assertEquals(m.locked, 0)
        self.assertEquals(m.publish_timestamp, 1445435155)

    def test_good_xml_full_generation(self):
        s = r'''<Event>
    <id>42</id>
    <org>ACME and bro.</org>
    <date>2015-10-20</date>
    <threat_level_id>3</threat_level_id>
    <info>AGNOSTIC PANDA</info>
    <published>1</published>
    <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
    <attribute_count>8</attribute_count>
    <analysis>2</analysis>
    <timestamp>1445434988</timestamp>
    <distribution>1</distribution>
    <proposal_email_lock>0</proposal_email_lock>
    <orgc>ACME Corporation</orgc>
    <locked>0</locked>
    <publish_timestamp>1445435155</publish_timestamp>
    </Event>
'''
        m = MispEvent.from_xml(s)
        new = m.to_xml()
        m = MispEvent.from_xml(new)
        self.assertEquals(m.uuid, '56278fd8-f2c0-4907-bcca-594e0a3ac101')
        self.assertEquals(m.id, 42)
        self.assertEquals(m.org, 'ACME and bro.')
        self.assertEquals(m.date, '2015-10-20')
        self.assertEquals(m.threat_level_id, 3)
        self.assertEquals(m.info, 'AGNOSTIC PANDA')
        self.assertEquals(m.published, 1)
        self.assertEquals(m.analysis, 2)
        self.assertEquals(m.timestamp, 1445434988)
        self.assertEquals(m.distribution, 1)
        self.assertEquals(m.orgc, 'ACME Corporation')
        self.assertEquals(m.locked, 0)
        self.assertEquals(m.publish_timestamp, 1445435155)

    def test_good_xml_generation(self):
        company = 'ACME Corporation'
        m = MispEvent()
        m.org = company
        serialized_evt = m.to_xml()
        obj = MispEvent.from_xml(serialized_evt)
        self.assertEquals(obj.org, company)

    def test_bad_xml(self):
        with self.assertRaises(lxml.etree.XMLSyntaxError):
            MispEvent.from_xml('<foo')

    def test_good_time_format(self):
        m = MispEvent()
        d = datetime.datetime.now()
        m.publish_timestamp = d
        self.assertEquals(m.publish_timestamp, int(time.mktime(d.timetuple())))


class MispAttrTest(unittest.TestCase):
    def test_bad_type(self):
        attr = MispAttribute()
        with self.assertRaises(ValueError):
            attr.type = 'foobar'

    def test_bad_category(self):
        attr = MispAttribute()
        with self.assertRaises(ValueError):
            attr.category = 'foobar'

    def test_bad_category(self):
        attr = MispAttribute()
        with self.assertRaises(ValueError):
            attr.distribution = 4

    def test_bad_threat_lvl(self):
        attr = MispAttribute()
        with self.assertRaises(ValueError):
            attr.threat_level_id = 5

    def test_bad_analysis(self):
        attr = MispAttribute()
        with self.assertRaises(ValueError):
            attr.analysis = 5

class MispServerTest(unittest.TestCase):
    def test_get_event(self):
        m = MispServer()
        evt = m.events.get(12)
        self.assertEquals(evt.id, 12)

if __name__ == '__main__':
    unittest.main()
