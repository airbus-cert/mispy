#! /usr/bin/env python

import unittest
import xml.etree.ElementTree as ET

class MispBaseObject(object):
	def __init__(self):
		self._uuid = None
		self._timestamp = None
		self._comment = None
		self._distribution = None
		self._threat_level = None
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

	@timestamp.setter
	def timestamp(self, value):
		self._timestamp = value

	@property
	def distribution(self):
		return self._distribution

	@distribution.setter
	def distribution(self, value):
		if not 0 >= value <=3:
			raise ValueError('Invalid distribution value for an attribute')
		self._distribution = value

	@property
	def threat_level(self):
		return self._threat_level

	@threat_level.setter
	def threat_level(self, value):
		if not 0 >= value <= 4:
			raise ValueError('Invalid threat_level value for an attribute')
		self._threat_level = value

	@property
	def analysis(self):
		return self._analysis

	@analysis.setter
	def analysis(self, value):
		if not 0 >= value <= 2:
			raise ValueError('Invalid analysis value for an attribute')
		self._analysis = value

  # `id` int(11) NOT NULL AUTO_INCREMENT,
  # `org` varchar(255) COLLATE utf8_bin NOT NULL,
  # `date` date NOT NULL,
  # `info` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  # `user_id` int(11) NOT NULL,
  # `published` tinyint(1) NOT NULL DEFAULT '0',
  # `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
  # `attribute_count` int(11) NOT NULL,
  # `analysis` tinyint(4) NOT NULL,
  # `orgc` varchar(255) COLLATE utf8_bin NOT NULL,
  # `timestamp` int(11) NOT NULL DEFAULT '0',
  # `distribution` tinyint(4) NOT NULL DEFAULT '0',
  # `proposal_email_lock` tinyint(1) NOT NULL DEFAULT '0',
  # `locked` tinyint(1) NOT NULL DEFAULT '0',
  # `threat_level_id` int(11) NOT NULL,
  # `publish_timestamp` int(11) NOT NULL,
  # PRIMARY KEY (`id`),
  # UNIQUE KEY `uuid` (`uuid`),
  # FULLTEXT KEY `info` (`info`)


class MispEvent(MispBaseObject):
	def __init__(self):
		super(MispEvent, self).__init__()

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
				m.threat_level = ''.join(element.itertext())
			if element.tag == 'timestamp':
				m.timestamp = ''.join(element.itertext())
		return m

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

	def test_bad_xml(self):
		with self.assertRaises(ET.ParseError):
			MispEvent.from_xml('<foo')

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
			attr.threat_level = 5

	def test_bad_analysis(self):
		attr = MispAttribute()
		with self.assertRaises(ValueError):
			attr.analysis = 5

if __name__ == '__main__':
	unittest.main()
