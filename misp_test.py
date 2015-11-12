#! /usr/bin/env python

#    This file is part of python-misp.
#
#   Copyright 2015 Nicolas Bareil <nicolas.bareil@airbus.com>
#                  while at Airbus Group CERT <http://www.airbus.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import unittest
from misp import *

class MispEventTest(unittest.TestCase):
    def test_good_xml(self):
        s = r"""<Event>
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
"""
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
        s = r"""<Event>
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
"""
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
    def test_fromtofrom_xml(self):
        s = r"""<Attribute>
      <id>87183</id>
      <type>regkey|value</type>
      <category>Persistence mechanism</category>
      <to_ids>1</to_ids>
      <uuid>562795f9-5723-4b96-8940-599b0a3ac101</uuid>
      <event_id>486</event_id>
      <distribution>1</distribution>
      <timestamp>1445434872</timestamp>
      <comment>loooool</comment>
      <value>lol</value>
      <ShadowAttribute/>
    </Attribute>"""
        a = MispAttribute.from_xml(s)
        s = a.to_xml()
        a = MispAttribute.from_xml(s)
        self.assertEquals(a.id, 87183)
        self.assertEquals(a.type, 'regkey|value')
        self.assertEquals(a.category, 'Persistence mechanism')
        self.assertEquals(a.to_ids, 1)
        self.assertEquals(a.uuid, '562795f9-5723-4b96-8940-599b0a3ac101')
        self.assertEquals(a.event_id, 486)
        self.assertEquals(a.distribution, 1)
        self.assertEquals(a.timestamp, 1445434872)
        self.assertEquals(a.comment, 'loooool')
        self.assertEquals(a.value, 'lol')

    def test_from_xml(self):
        s = r"""<Attribute>
      <id>87183</id>
      <type>regkey|value</type>
      <category>Persistence mechanism</category>
      <to_ids>1</to_ids>
      <uuid>562795f9-5723-4b96-8940-599b0a3ac101</uuid>
      <event_id>486</event_id>
      <distribution>1</distribution>
      <timestamp>1445434872</timestamp>
      <comment>loooool</comment>
      <value>lol</value>
      <ShadowAttribute/>
    </Attribute>"""
        a = MispAttribute.from_xml(s)
        self.assertEquals(a.id, 87183)
        self.assertEquals(a.type, 'regkey|value')
        self.assertEquals(a.category, 'Persistence mechanism')
        self.assertEquals(a.to_ids, 1)
        self.assertEquals(a.uuid, '562795f9-5723-4b96-8940-599b0a3ac101')
        self.assertEquals(a.event_id, 486)
        self.assertEquals(a.distribution, 1)
        self.assertEquals(a.timestamp, 1445434872)
        self.assertEquals(a.comment, 'loooool')
        self.assertEquals(a.value, 'lol')

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

    def test_good_inner_attribute(self):
        attr = MispAttribute()


class MispServerTest(unittest.TestCase):
    def test_get_event(self):
        m = MispServer()
        evt = m.events.get(TEST_EVT_ID)
        self.assertEquals(evt.id, TEST_EVT_ID)

    def test_search_event(self):
        m = MispServer()
        evt=m.events.search(value=TEST_NEEDLE)
        self.assertEquals(len(evt), 1)
        self.assertEquals(evt[0].id, TEST_EVT_ID)
        ok=False
        for event in evt:
            for attr in event.attributes:
                if attr.value == TEST_NEEDLE:
                    ok=True
                    break
        self.assertEquals(ok, True)

    def disabled_test_last(self):
        m = MispServer()
        self.assertEquals(m.events.last().id, TEST_LAST_EVT_ID)

    def disabled_test_create_event(self):
        m = MispServer()
        e = MispEvent()
        e.info = 'Hello world'
        e.orgc = DEFAULT_ORGC
        e.org = DEFAULT_ORG
        e.published = 0
        e.distribution = 0
        m.events.put(e)

    def test_modify_event(self):
        m = MispServer()
        e = m.events.get(TEST_EVT_ID)
        e.timestamp = datetime.datetime.now()
        a = MispAttribute()
        a.value='foobar%d.com' % time.time()
        a.comment='evil domain'
        a.category = 'Network activity'
        a.type = 'domain'
        e.attributes.add(a)
        m.events.update(e)

    def test_modify_attr(self):
        m = MispServer()
        event = m.events.get(TEST_EVT_ID)
        updateme=None
        for attr in event.attributes:
            if str(attr.value).startswith('tata'):
                updateme=attr
                break
        self.assertIsNotNone(updateme)
        updateme.comment='Hello; %s' % datetime.datetime.now()
        m.attributes.update(updateme)

if __name__ == '__main__':
    unittest.main()
