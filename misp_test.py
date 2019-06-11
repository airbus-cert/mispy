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
        self.assertEqual(m.uuid, '56278fd8-f2c0-4907-bcca-594e0a3ac101')
        self.assertEqual(m.id, 42)
        self.assertEqual(m.org, 'ACME and bro.')
        self.assertEqual(m.date, '2015-10-20')
        self.assertEqual(m.threat_level_id, 3)
        self.assertEqual(m.info, 'AGNOSTIC PANDA')
        self.assertEqual(m.published, 1)
        self.assertEqual(m.analysis, 2)
        self.assertEqual(m.timestamp, 1445434988)
        self.assertEqual(m.distribution, 1)
        self.assertEqual(m.orgc, 'ACME Corporation')
        self.assertEqual(m.locked, 0)
        self.assertEqual(m.publish_timestamp, 1445435155)
        for attr in m.attributes:
            self.assertEqual(attr.value, 'a283e768fa12ef33087f07b01f82d6dd')

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
        self.assertEqual(m.uuid, '56278fd8-f2c0-4907-bcca-594e0a3ac101')
        self.assertEqual(m.id, 42)
        self.assertEqual(m.org, 'ACME and bro.')
        self.assertEqual(m.date, '2015-10-20')
        self.assertEqual(m.threat_level_id, 3)
        self.assertEqual(m.info, 'AGNOSTIC PANDA')
        self.assertEqual(m.published, 1)
        self.assertEqual(m.analysis, 2)
        self.assertEqual(m.timestamp, 1445434988)
        self.assertEqual(m.distribution, 1)
        self.assertEqual(m.orgc, 'ACME Corporation')
        self.assertEqual(m.locked, 0)
        self.assertEqual(m.publish_timestamp, 1445435155)

    def test_good_xml_generation(self):
        company = 'ACME Corporation'
        m = MispEvent()
        m.org = company
        serialized_evt = m.to_xml()
        obj = MispEvent.from_xml(serialized_evt)
        self.assertEqual(obj.org, company)

    def test_bad_xml(self):
        with self.assertRaises(lxml.etree.XMLSyntaxError):
            MispEvent.from_xml('<foo')

    def test_good_time_format(self):
        m = MispEvent()
        d = datetime.datetime.now()
        m.publish_timestamp = d
        self.assertEqual(m.publish_timestamp, int(time.mktime(d.timetuple())))

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
        self.assertEqual(m.uuid, '56278fd8-f2c0-4907-bcca-594e0a3ac101')
        self.assertEqual(m.id, 42)
        self.assertEqual(m.org, 'ACME and bro.')
        self.assertEqual(m.date, '2015-10-20')
        self.assertEqual(m.threat_level_id, 3)
        self.assertEqual(m.info, 'AGNOSTIC PANDA')
        self.assertEqual(m.published, 1)
        self.assertEqual(m.analysis, 2)
        self.assertEqual(m.timestamp, 1445434988)
        self.assertEqual(m.distribution, 1)
        self.assertEqual(m.orgc, 'ACME Corporation')
        self.assertEqual(len(m.tags), 3)


class MispTagTest(unittest.TestCase):
    def test_from_xml(self):
        s = r"""
        <Tag><id>3</id><name>TLP:GREEN</name><colour>#04cc18</colour><exportable>1</exportable><org_id>0</org_id></Tag>
        """
        tag = MispTag.from_xml(s)
        self.assertEqual(tag.id, 3)
        self.assertEqual(tag.name, "TLP:GREEN")
        self.assertEqual(tag.colour, "#04cc18")
        self.assertEqual(tag.exportable, True)
        self.assertEqual(tag.org_id, 0)


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
        self.assertEquals(a.type, 'md5')
        self.assertEquals(a.category, 'Payload delivery')
        self.assertEquals(a.to_ids, 1)
        self.assertEquals(a.uuid, '56c577ed-94e0-4446-a639-40200a3ac101')
        self.assertEquals(a.event_id, 42)
        self.assertEquals(a.distribution, 5)
        self.assertEquals(a.timestamp, 1445434872)
        self.assertEquals(a.comment, 'loooool')
        self.assertEquals(a.value, 'a283e768fa12ef33087f07b01f82d6dd')
        self.assertEqual(a.value.__class__, str)

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
        self.assertEqual(a.id, 87183)
        self.assertEqual(a.type, 'md5')
        self.assertEqual(a.category, 'Payload delivery')
        self.assertEqual(a.to_ids, 1)
        self.assertEqual(a.uuid, '56c577ed-94e0-4446-a639-40200a3ac101')
        self.assertEqual(a.event_id, 42)
        self.assertEqual(a.distribution, 5)
        self.assertEqual(a.timestamp, 1445434872)
        self.assertEqual(a.comment, 'loooool')
        self.assertEqual(a.value, 'a283e768fa12ef33087f07b01f82d6dd')

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

        valid_types = ['AS', 'aba-rtn', 'anonymised', 'attachment',
                'authentihash', 'bank-account-nr', 'bic', 'bin', 'boolean',
                'bro', 'btc', 'campaign-id', 'campaign-name', 'cc-number',
                'cdhash', 'comment', 'cookie', 'cortex', 'counter',
                'country-of-residence', 'cpe', 'date-of-birth', 'datetime',
                'dns-soa-email', 'domain', 'domain|ip', 'email-attachment',
                'email-body', 'email-dst', 'email-dst-display-name',
                'email-header', 'email-message-id', 'email-mime-boundary',
                'email-reply-to', 'email-src', 'email-src-display-name',
                'email-subject', 'email-thread-index', 'email-x-mailer',
                'filename', 'filename|authentihash', 'filename|impfuzzy',
                'filename|imphash', 'filename|md5', 'filename|pehash',
                'filename|sha1', 'filename|sha224', 'filename|sha256',
                'filename|sha384', 'filename|sha512', 'filename|sha512/224',
                'filename|sha512/256', 'filename|ssdeep', 'filename|tlsh',
                'first-name', 'float', 'frequent-flyer-number', 'gender',
                'gene', 'github-organisation', 'github-repository',
                'github-username', 'hassh-md5', 'hasshserver-md5', 'hex',
                'hostname', 'hostname|port', 'http-method', 'iban',
                'identity-card-number', 'impfuzzy', 'imphash', 'ip-dst',
                'ip-dst|port', 'ip-src', 'ip-src|port', 'issue-date-of-the-visa',
                'ja3-fingerprint-md5', 'jabber-id', 'last-name', 'link',
                'mac-address', 'mac-eui-64', 'malware-sample', 'malware-type',
                'md5', 'middle-name', 'mime-type', 'mobile-application-id',
                'mutex', 'named', 'nationality', 'other',
                'passenger-name-record-locator-number', 'passport-country',
                'passport-expiration', 'passport-number', 'pattern-in-file',
                'pattern-in-memory', 'pattern-in-traffic', 'payment-details',
                'pdb', 'pehash', 'phone-number', 'place-of-birth',
                'place-port-of-clearance', 'place-port-of-onward-foreign-destination',
                'place-port-of-original-embarkation', 'port', 'primary-residence',
                'prtn', 'redress-number', 'regkey', 'regkey|value', 'sha1',
                'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224',
                'sha512/256', 'sigma', 'size-in-bytes', 'snort',
                'special-service-request', 'ssdeep', 'stix2-pattern',
                'target-email', 'target-external', 'target-location',
                'target-machine', 'target-org', 'target-user', 'text',
                'threat-actor', 'tlsh', 'travel-details', 'twitter-id', 'uri',
                'url', 'user-agent', 'visa-number', 'vulnerability',
                'whois-creation-date', 'whois-registrant-email', 'whois-registrant-name',
                'whois-registrant-org', 'whois-registrant-phone', 'whois-registrar',
                'windows-scheduled-task', 'windows-service-displayname',
                'windows-service-name', 'x509-fingerprint-md5', 'x509-fingerprint-sha1',
                'x509-fingerprint-sha256', 'xmr', 'yara', 'zeek']

        for t in valid_types:
            attr.type = t


class MispServerTest(unittest.TestCase):
    def disabled_test_get_event(self):
        m = MispServer()
        evt = m.events.get(TEST_EVT_ID)
        self.assertEqual(evt.id, TEST_EVT_ID)

    def disabled_test_search_event(self):
        m = MispServer()
        evt=m.events.search(value=TEST_NEEDLE)
        self.assertEqual(len(evt), 1)
        self.assertEqual(evt[0].id, TEST_EVT_ID)
        ok=False
        for event in evt:
            for attr in event.attributes:
                if attr.value == TEST_NEEDLE:
                    ok=True
                    break
        self.assertEqual(ok, True)

    def disabled_test_last(self):
        m = MispServer()
        self.assertEqual(m.events.last().id, TEST_LAST_EVT_ID)

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
    def test_python3_bug(self):
        err = MispTransportError('POST %s: returned status=%d', '/stuff', 404)
        self.assertEqual(err.path, '/stuff')
        self.assertEqual(err.status_code, 404)
        try:
            self.assertEqual(err[2], 404)
        except TypeError:
            # That's ok it means you are testing with python 3
            pass
        self.assertEqual(err.args[2], 404)


class MispObjectTest(unittest.TestCase):
    def test_from_xml(self):
        xml = """<Object>
    <id>1234</id>
    <name>file</name>
    <meta-category>file</meta-category>
    <description>File object describing a file with meta-information</description>
    <template_uuid>688c46fb-5edb-40a3-8273-1af7923e2215</template_uuid>
    <template_version>13</template_version>
    <event_id>9876</event_id>
    <uuid>5c9c8b6f-bb24-4e6c-ab83-18c60a3a5cf9</uuid>
    <timestamp>1553763183</timestamp>
    <distribution>1</distribution>
    <sharing_group_id>0</sharing_group_id>
    <comment>Hello</comment>
    <deleted>0</deleted>
    <ObjectReference/>
    <Attribute>
      <id>2640682</id>
      <type>malware-sample</type>
      <category>Payload installation</category>
      <to_ids>1</to_ids>
      <uuid>5c9c8b70-4814-493b-a891-18c60a3a5cf9</uuid>
      <event_id>14584</event_id>
      <distribution>1</distribution>
      <timestamp>1553763184</timestamp>
      <comment/>
      <sharing_group_id>0</sharing_group_id>
      <deleted>0</deleted>
      <disable_correlation>0</disable_correlation>
      <object_id>292731</object_id>
      <object_relation>malware-sample</object_relation>
      <value>/tmp/a.exe|d41d8cd98f00b204e9800998ecf8427e</value>
      <Galaxy/>
      <data>abcdef</data>
      <ShadowAttribute/>
    </Attribute>
    <Attribute>
      <id>2640683</id>
      <type>filename</type>
      <category>Payload installation</category>
      <to_ids>0</to_ids>
      <uuid>5c9c8b73-0418-474f-a2ee-18c60a3a5cf9</uuid>
      <event_id>14584</event_id>
      <distribution>1</distribution>
      <timestamp>1553763187</timestamp>
      <comment/>
      <sharing_group_id>0</sharing_group_id>
      <deleted>0</deleted>
      <disable_correlation>0</disable_correlation>
      <object_id>292731</object_id>
      <object_relation>filename</object_relation>
      <value>/tmp/a.exe</value>
      <Galaxy/>
      <ShadowAttribute/>
    </Attribute>
  </Object>"""

        obj = MispObject.from_xml(xml)
        self.assertEqual(obj.id, 1234)
        self.assertEqual(obj.name, "file")
        self.assertEqual(obj.comment, "Hello")
        self.assertEqual(obj.event_id, 9876)
        self.assertEqual(obj.timestamp, 1553763183)
        self.assertEqual(obj.meta_category, "file")
        self.assertEqual(len(obj.attributes), 2)


if __name__ == '__main__':
    unittest.main()
