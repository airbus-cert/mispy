#! /usr/bin/env python

import unittest
import xml.etree.ElementTree as ET
import lxml
from lxml import objectify
import time
import datetime

DEFAULT_ORG = 'ACME Corp.'
DEFAULT_ORGC = 'ACME Corp.'

class MispBaseObject(object):
    def __init__(self):
        self._uuid = None
        self._timestamp = None
        self._comment = None
        self._distribution = None
        self._threat_level_id = None
        self._analysis = None

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
        return self._timestamp

    @property
    def timestamp(self):
        if self._timestamp:
            return self._timestamp
        return int(time.time())

    @timestamp.setter
    def timestamp(self, value):
        val = None
        if type(value) is int:
            val = self._timestamp
        elif type(value) is datetime.datetime:
            val = int(time.mktime(value.timetuple()))
        self._timestamp = val

    @property
    def distribution(self):
        return self._distribution or 0

    @distribution.setter
    def distribution(self, value):
        if not 0 >= int(value) <=3:
            raise ValueError('Invalid distribution value for an attribute')
        self._distribution = value

    @property
    def threat_level_id(self):
        return self._threat_level_id or 0

    @threat_level_id.setter
    def threat_level_id(self, value):
        if not 0 >= int(value) <= 4:
            raise ValueError('Invalid threat_level_id value for an attribute')
        self._threat_level = value

    @property
    def analysis(self):
        return self._analysis

    @analysis.setter
    def analysis(self, value):
        if not 0 >= value <= 2:
            raise ValueError('Invalid analysis value for an attribute')
        self._analysis = value


class MispEvent(MispBaseObject):
    def __init__(self):
        super(MispEvent, self).__init__()
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
        return self._org

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
        if type(value) is int:
            val = value
        elif type(value) is datetime.datetime:
            val = value.strftime('%Y-%m-%d')
        self._date = val

    @property
    def publish_timestamp(self):
        if self._publish_timestamp:
            return self._publish_timestamp
        return int(time.time())

    @publish_timestamp.setter
    def publish_timestamp(self, value):
        val = None
        if type(value) is int:
            val = value
        elif type(value) is datetime.datetime:
            val = int(time.mktime(value.timetuple()))
        self._publish_timestamp = val

    @staticmethod
    def from_xml(s):
        tree = ET.fromstring(s)
        if tree.tag.lower() != 'event':
            raise ValueError('Invalid Event XML')
        m = MispEvent()
        for element in tree:
            if element.tag == 'uuid':
                m.uuid = ''.join(element.itertext())
            if element.tag == 'distribution':
                m.distribution = ''.join(element.itertext())
            if element.tag == 'threat_level_id':
                m.threat_level_id = ''.join(element.itertext())
            if element.tag == 'timestamp':
                m.timestamp = ''.join(element.itertext())
            if element.tag == 'publish_timestamp':
                m.publish_timestamp = ''.join(element.itertext())
            if element.tag == 'orgc':
                m.orgc = ''.join(element.itertext())
            if element.tag == 'org':
                m.org = ''.join(element.itertext())
            if element.tag == 'timestamp':
                m.timestamp = ''.join(element.itertext())
        return m

    def to_xml(self):
        event = self.to_xml_object()
        lxml.objectify.deannotate(event, xsi_nil=True)
        lxml.etree.cleanup_namespaces(event)
        return lxml.etree.tostring(event)

    def to_xml_object(self):
        event = objectify.Element('event')
        for field in ['uuid', 'distribution', 'threat_level_id', 'org',
                      'orgc', 'date', 'info', 'published', 'attribute_count',
                      'analysis', 'timestamp', 'distribution', 'proposal_email_lock',
                      'locked', 'publish_timestamp']:
            val = getattr(self, field)
            setattr(event, field, val)
        for attr in self.attributes:
            event.append(attr.to_xml_object())
        return event

class MispServer(object):
    def do(self, http_method, url, body):
        pass
    def POST(url, body):
        return self.do('POST', url, body)
    def GET(url, body):
        return self.do('GET', url, body)

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
    def ids(self):
        return self._ids

    @ids.setter
    def ids(self, value):
        self._ids = value


class MispEventTest(unittest.TestCase):
    def test_good_xml(self):
        s = '<event><uuid>3BEC4A95-46AD-4209-86A2-D2C77A55C8D2</uuid></event>'
        m = MispEvent.from_xml(s)
        self.assertEquals(m.uuid, '3BEC4A95-46AD-4209-86A2-D2C77A55C8D2')

    def test_good_xml_generation(self):
        company = 'ACME Corporation'
        m = MispEvent()
        m.org = company
        serialized_evt = m.to_xml()
        print serialized_evt
        obj = MispEvent.from_xml(serialized_evt)
        self.assertEquals(obj.org, company)

    def test_bad_xml(self):
        with self.assertRaises(ET.ParseError):
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

if __name__ == '__main__':
    unittest.main()
