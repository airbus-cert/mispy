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
from mispy.misp import *


class MispEventTest(unittest.TestCase):
    def test_good_xml(self):
        s = r"""<Event>
  <id>42</id>
  <orgc_id>2</orgc_id>
  <org_id>2</org_id>
  <date>2015-10-20</date>
  <threat_level_id>3</threat_level_id>
  <info>AGNOSTIC PANDA</info>
  <published>1</published>
  <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
  <analysis>2</analysis>
  <timestamp>1445434988</timestamp>
  <distribution>1</distribution>
  <publish_timestamp>1445435155</publish_timestamp>
  <sharing_group_id>0</sharing_group_id>
  <Org>
    <id>2</id>
    <name>ACME and bro.</name>
    <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
  </Org>
  <Orgc>
    <id>2</id>
    <name>ACME Corporation</name>
    <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
  </Orgc>
  <Attribute>
    <id>4442</id>
    <type>md5</type>
    <category>Payload delivery</category>
    <to_ids>1</to_ids>
    <uuid>56c577ed-94e0-4446-a639-40200a3ac101</uuid>
    <event_id>1172</event_id>
    <distribution>5</distribution>
    <timestamp>1455781869</timestamp>
    <comment/>
    <sharing_group_id>0</sharing_group_id>
    <value>a283e768fa12ef33087f07b01f82d6dd</value>
    <ShadowAttribute/>
  </Attribute>
  <ShadowAttribute/>
  <RelatedEvent/>
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
        for attr in m.attributes:
            self.assertEquals(attr.value, 'a283e768fa12ef33087f07b01f82d6dd')

    def test_good_xml_full_generation(self):
        s = r"""<Event>
    <id>42</id>
    <Org>
      <name>ACME and bro.</name>
      <id>12</id>
      <uuid>464d9146-2c34-43df-906a-7bc40a3ac101</uuid>
    </Org>
    <Orgc>
      <name>ACME Corporation</name>
      <id>13</id>
      <uuid>164d9146-2c34-43df-906a-7bc40a3ac101</uuid>
    </Orgc>    <date>2015-10-20</date>
    <threat_level_id>3</threat_level_id>
    <info>AGNOSTIC PANDA</info>
    <published>1</published>
    <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
    <attribute_count>8</attribute_count>
    <analysis>2</analysis>
    <timestamp>1445434988</timestamp>
    <distribution>1</distribution>
    <proposal_email_lock>0</proposal_email_lock>
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

    def test_tags_in_good_xml(self):
        s = r"""<Event>
  <id>42</id>
  <orgc_id>2</orgc_id>
  <org_id>2</org_id>
  <date>2015-10-20</date>
  <threat_level_id>3</threat_level_id>
  <info>AGNOSTIC PANDA</info>
  <published>1</published>
  <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
  <analysis>2</analysis>
  <timestamp>1445434988</timestamp>
  <distribution>1</distribution>
  <publish_timestamp>1445435155</publish_timestamp>
  <sharing_group_id>0</sharing_group_id>
  <Org>
    <id>2</id>
    <name>ACME and bro.</name>
    <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
  </Org>
  <Orgc>
    <id>2</id>
    <name>ACME Corporation</name>
    <uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid>
  </Orgc>
  <Attribute>
    <id>4442</id>
    <type>md5</type>
    <category>Payload delivery</category>
    <to_ids>1</to_ids>
    <uuid>56c577ed-94e0-4446-a639-40200a3ac101</uuid>
    <event_id>1172</event_id>
    <distribution>5</distribution>
    <timestamp>1455781869</timestamp>
    <comment/>
    <sharing_group_id>0</sharing_group_id>
    <value>a283e768fa12ef33087f07b01f82d6dd</value>
    <ShadowAttribute/>
  </Attribute>
  <ShadowAttribute/>
  <RelatedEvent/>
  <Tag><id>5</id><name>APT1</name><colour>#ffad0d</colour><exportable>1</exportable><org_id>0</org_id></Tag>
  <Tag><id>3</id><name>TLP:RED</name><colour>#04cc18</colour><exportable>1</exportable><org_id>0</org_id></Tag>
  <Tag><id>7</id><name>CONFIDENTIAL</name><colour>#cccccc</colour><exportable>1</exportable><org_id>0</org_id></Tag>
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
        self.assertEquals(len(m.tags), 3)


class MispTagTest(unittest.TestCase):
    def test_from_xml(self):
        s = r"""
        <Tag><id>3</id><name>TLP:GREEN</name><colour>#04cc18</colour><exportable>1</exportable><org_id>0</org_id></Tag>
        """
        tag = MispTag.from_xml(s)
        self.assertEquals(tag.id, 3)
        self.assertEquals(tag.name, "TLP:GREEN")
        self.assertEquals(tag.colour, "#04cc18")
        self.assertEquals(tag.exportable, True)
        self.assertEquals(tag.org_id, 0)


class MispAttrTest(unittest.TestCase):
    def test_fromtofrom_xml(self):
        s = r"""<Attribute>
    <id>87183</id>
    <type>md5</type>
    <category>Payload delivery</category>
    <to_ids>1</to_ids>
    <uuid>56c577ed-94e0-4446-a639-40200a3ac101</uuid>
    <event_id>42</event_id>
    <distribution>5</distribution>
    <timestamp>1445434872</timestamp>
    <comment>loooool</comment>
    <sharing_group_id>0</sharing_group_id>
    <value>a283e768fa12ef33087f07b01f82d6dd</value>
    <ShadowAttribute/>
  </Attribute>"""
        a = MispAttribute.from_xml(s)
        s = a.to_xml()
        a = MispAttribute.from_xml(s)
        self.assertEquals(a.id, 87183)
        self.assertEquals(a.type, 'md5')
        self.assertEquals(a.category, 'Payload delivery')
        self.assertEquals(a.to_ids, 1)
        self.assertEquals(a.uuid, '56c577ed-94e0-4446-a639-40200a3ac101')
        self.assertEquals(a.event_id, 42)
        self.assertEquals(a.distribution, 5)
        self.assertEquals(a.timestamp, 1445434872)
        self.assertEquals(a.comment, 'loooool')
        self.assertEquals(a.value, 'a283e768fa12ef33087f07b01f82d6dd')

    def test_from_xml(self):
        s = r"""<Attribute>
    <id>87183</id>
    <type>md5</type>
    <category>Payload delivery</category>
    <to_ids>1</to_ids>
    <uuid>56c577ed-94e0-4446-a639-40200a3ac101</uuid>
    <event_id>42</event_id>
    <distribution>5</distribution>
    <timestamp>1445434872</timestamp>
    <comment>loooool</comment>
    <sharing_group_id>0</sharing_group_id>
    <value>a283e768fa12ef33087f07b01f82d6dd</value>
    <ShadowAttribute/>
  </Attribute>"""
        a = MispAttribute.from_xml(s)
        self.assertEquals(a.id, 87183)
        self.assertEquals(a.type, 'md5')
        self.assertEquals(a.category, 'Payload delivery')
        self.assertEquals(a.to_ids, 1)
        self.assertEquals(a.uuid, '56c577ed-94e0-4446-a639-40200a3ac101')
        self.assertEquals(a.event_id, 42)
        self.assertEquals(a.distribution, 5)
        self.assertEquals(a.timestamp, 1445434872)
        self.assertEquals(a.comment, 'loooool')
        self.assertEquals(a.value, 'a283e768fa12ef33087f07b01f82d6dd')

    def test_bad_category(self):
        attr = MispAttribute()
        with self.assertRaises(ValueError):
            attr.category = 'foobar'

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

    def test_bad_types(self):
        attr = MispAttribute()
        with self.assertRaises(ValueError):
            attr.type = 'foobar'

        valid_types = ['md5', 'sha1', 'sha256', 'filename', 'pdb',
            'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src',
            'ip-dst', 'hostname', 'domain', 'domain|ip', 'email-src', 'email-dst',
            'email-subject', 'email-attachment', 'url', 'http-method', 'user-agent',
            'regkey', 'regkey|value', 'AS', 'snort', 'pattern-in-file',
            'pattern-in-traffic', 'pattern-in-memory', 'yara', 'vulnerability',
            'attachment', 'malware-sample', 'link', 'comment', 'text', 'other',
            'named pipe', 'mutex', 'target-user', 'target-email', 'target-machine',
            'target-org', 'target-location', 'target-external', 'btc', 'iban',
            'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn',
            'threat-actor', 'campaign-name', 'campaign-id', 'malware-type',
            'uri', 'authentihash', 'ssdeep', 'imphash', 'pehash', 'sha224',
            'sha384', 'sha512', 'sha512/224', 'sha512/256', 'tlsh',
            'filename|authentihash', 'filename|ssdeep', 'filename|imphash',
            'filename|pehash', 'filename|sha224', 'filename|sha384',
            'filename|sha512', 'filename|sha512/224', 'filename|sha512/256',
            'filename|tlsh', 'windows-scheduled-task', 'windows-service-name',
            'windows-service-displayname', 'whois-registrant-email',
            'whois-registrant-phone', 'whois-registrant-name', 'whois-registrar',
            'whois-creation-date', 'targeted-threat-index', 'mailslot', 'pipe',
            'ssl-cert-attributes', 'x509-fingerprint-sha1']
        for t in valid_types:
            attr.type = t


class MispServerTest(unittest.TestCase):
    def disabled_test_get_event(self):
        m = MispServer()
        evt = m.events.get(TEST_EVT_ID)
        self.assertEquals(evt.id, TEST_EVT_ID)

    def disabled_test_search_event(self):
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

    def disabled_test_modify_event(self):
        m = MispServer()
        e = m.events.get(TEST_EVT_ID)
        e.timestamp = datetime.datetime.now()
        a = MispAttribute()
        a.value = 'foobar%d.com' % time.time()
        a.comment = 'evil domain'
        a.category = 'Network activity'
        a.type = 'domain'
        e.attributes.add(a)
        m.events.update(e)

    def disabled_test_modify_attr(self):
        m = MispServer()
        event = m.events.get(TEST_EVT_ID)
        updateme = None
        for attr in event.attributes:
            if str(attr.value).startswith('tata'):
                updateme = attr
                break
        self.assertIsNotNone(updateme)
        updateme.comment = 'Hello; %s' % datetime.datetime.now()
        m.attributes.update(updateme)


class MispTransportErrorTest(unittest.TestCase):
    def python3_bug(self):
        try:
            raise MispTransportError('POST %s: returned status=%d', '/stuff', 404)
        except MispTransportError as err:
            self.assertEquals(err.path, '/stuff/')
            self.assertEquals(err.response_code, 404)


if __name__ == '__main__':
    unittest.main()
