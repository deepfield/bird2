import unittest
import ipaddress

import explain_mrt.explain as TN

import df.mrtanalysis.structure


class TestMRTObject(unittest.TestCase):
    CT = TN.MRTObject

    def test_init(self):
        actual = self.CT( 10)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 10)


class TestMRTPrefix(unittest.TestCase):
    CT = TN.MRTPrefix

    def test_unpack_from_ipv4(self):
        packed = b'\x18\x00\x00\x00'
        actual = self.CT.unpack_from(4, packed, 0)
        self.assertIsInstance(actual, self.CT)
        # self.assertIsInstance(actual.prefix, ipaddress.IPv4Network)
        self.assertEqual(3, actual.size, 3)
        self.assertEqual(4, actual.nbytes)
        self.assertEqual(actual.prefix, ipaddress.IPv4Network( "0.0.0.0/24"))


class TestMRTType(unittest.TestCase):
    CT = TN.MRTType

    def test_init(self):
        actual = self.CT(12)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 2)


class TestMRTSubType(unittest.TestCase):
    CT = TN.MRTSubType

    def test_init(self):
        actual = self.CT(4)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 1)

    def test_str(self):
        actual = self.CT(4)
        self.assertEqual(str(actual), "RIB_IPV6_UNICAST")

    def test_str_unkown(self):
        actual = self.CT(2000)
        self.assertEqual(str(actual), "MRTSubType: unknown 0x07d0")


class TestMRTHeader(unittest.TestCase):
    CT = df.mrtanalysis.structure.MRTHeader

    def test_init(self):
        actual = self.CT(0, 13, 4, 12, 12)
        self.assertIsInstance(actual, self.CT)

    def test_unpack_from(self):
        packed = b"\x5e\x27\x66\x4b\x00\x0d\x00\x01\x00\x00\x00\x35"
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual._timestamp, 0x5E27664B)
        self.assertIsInstance(actual.type, TN.MRTType)
        self.assertEqual(actual.type.code, 13)
        self.assertIsInstance(actual.subtype, TN.MRTSubType)
        self.assertEqual(actual.subtype.code, 1)
        self.assertEqual(len(actual), 53)
        self.assertEqual(actual.nbytes, 12)


class TestPeerType(unittest.TestCase):
    CT = TN.PeerType

    def test_init(self):
        pass

    def test_unpack_from(self):
        packed = b"\x03"
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.ipversion, 6)
        self.assertTrue(actual.is_ipv6)
        self.assertEqual(actual.ipaddress_size, 16)
        self.assertEqual(actual.nbytes, 1)


class TestPeerIndexEntry(unittest.TestCase):
    CT = TN.PeerIndexEntry

    def test_unpack_from(self):
        packed = b"\x03" + b"\x00" * 4 + b"\x00" * 16 + b"\x00" * 4
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 25)

    def test_unpack_from2(self):
        packed = (
            b"\x02" + b"\x14\x00\x00\x00" + b"\xac\x15\x00\x07" + b"\x00\x00\xfe\x4c"
        )
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 13)


class TestPeerIndexTable(unittest.TestCase):
    CT = TN.PeerIndexTable

    def test_unpack_from(self):
        packed = (
            b"\x0a\x00\x00\x01"
            + b"\x00\x07"
            + b"master6"
            + b"\x00\x02"
            + b"\x03"
            + b"\x00" * 4
            + b"\x00" * 16
            + b"\x00" * 4
            + b"\x02"
            + b"\x14\x00\x00\x00"
            + b"\xac\x15\x00\x07"
            + b"\x00\x00\xfe\x4c"
        )
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 53)


class TestBGPAttrFlag(unittest.TestCase):
    CT = TN.BGPAttrFlag

    def test_unpack_from(self):
        packed = b"\x40"
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 1)
        self.assertTrue(actual.transitive)
        self.assertFalse(actual.optional)
        self.assertFalse(actual.extended_length)
        self.assertFalse(actual.partial)

    def test_explain(self):
        packed = b"\x40"
        testee = self.CT.unpack_from(packed, 0)
        actual = testee.explain()
        self.assertIsInstance(actual, list)
        self.assertEqual( len(actual), 5)


class TestBGPAttrHeader(unittest.TestCase):
    CT = TN.BGPAttrHeader

    def test_unpack_from(self):
        packed = b"\x40\x01\x01"
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, tuple)
        self.assertEqual(len(actual), 5)
        self.assertIsInstance(actual[0], TN.BGPAttrFlag)
        self.assertTrue(actual[0].transitive)
        self.assertEqual(actual[1], 1)
        self.assertEqual(actual[2], 1)
        self.assertEqual(actual[3], 1)
        self.assertEqual(actual[4], 3)


class TestBGPAttrOrigin(unittest.TestCase):
    CT = TN.BGPAttrOrigin

    def test_unpack_from(self):
        packed = b"\x40\x01\x01\x02"
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(4, actual.nbytes)
        self.assertTrue(actual.is_incomplete)


class TestBGPAttrASPath(unittest.TestCase):
    CT = TN.BGPAttrASPath

    def test_unpack_from(self):
        packed = b"\x40\x02\x06\x02\x01\x00\x00\xfe\x4c"
        actual = self.CT.unpack_from(4, packed, 0)
        self.assertIsInstance(actual,self.CT)
        self.assertEqual(actual.nbytes, 9)
        self.assertEqual(actual.type, 2)
        self.assertEqual(actual.header_size, 3)
        self.assertEqual(actual.asn_size, 4)


class TestBGPAttrNextHop(unittest.TestCase):
    CT = TN.BGPAttrNextHop

    def test_unpack_from(self):
        packed = b"\x40\x03\x04\xac\x15\x00\x07"
        actual = self.CT.unpack_from(4, packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertTrue(actual.flag.transitive)
        self.assertEqual(actual.nbytes, 7)
        self.assertEqual(actual.next_hop, ipaddress.IPv4Address("172.21.0.7"))
        self.assertEqual(actual.ip_version, 4)


class TestBGPAttrLocalPref(unittest.TestCase):
    CT = TN.BGPAttrLocalPref

    def test_unpack_from(self):
        packed = b"\x40\x05\x04\x08\x08\x08\x08"
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertTrue(actual.flag.transitive)
        self.assertEqual(7, actual.nbytes)
        self.assertEqual(0x08080808, actual.value)


class TestBGPAttrMPReachNLRI(unittest.TestCase):
    CT = TN.BGPAttrMPReachNLRI

    def test_unpack_from(self):
        packed = b""
        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)


class TestBGPAttributeFactory(unittest.TestCase):
    CT = TN.BGPAttributeFactory

    def test_decode_attributes(self):
        packed = b"\x40\x03\x04\xac\x15\x00\x07"
        (actual, consumed) = self.CT.decode_attributes(4, 2, packed, len(packed), 0)
        self.assertEqual(consumed, len(packed))
        self.assertIsInstance(actual, list)
        self.assertEqual(1, len(actual))
        self.assertIsInstance(actual[0], TN.BGPAttrNextHop)


class TestBGPAttributes(unittest.TestCase):
    CT = TN.BGPAttributes

    def test_unpack_from(self):
        packed = b"\x40\x01\x01\x02\x40\x02\x06\x02\x01\x00\x00\xfe\x4c"
        actual = self.CT.unpack_from(4, 4, len(packed), packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(13, actual.nbytes)
        self.assertEqual(2, len(actual))
        self.assertEqual(4, actual.asn_size)
        self.assertIsInstance(actual.attributes[0], TN.BGPAttrOrigin)
        self.assertIsInstance(actual.attributes[1], TN.BGPAttrASPath)


class TestRibTableEntry(unittest.TestCase):
    CT = TN.RibTableEntry

    def test_init(self):
        actual = self.CT( 10)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.nbytes, 10)


class TestRibTableEntryIPV6Unicast(unittest.TestCase):
    CT = TN.RibTableEntryIPv6Unicast

    def test_unpack_from(self):
        packed = b"\x00\x01"\
                 b"\x5e\x27\x66\x11"\
                 b"\x00\x14"\
                 b"\x40\x01\x01\x02"\
                 b"\x40\x02\x06\x02\x01\x00\x00\xfe\x4c"\
                 b"\x00\x05\x04\x00\x00\x00\x00"
        actual = self.CT.unpack_from(4, packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(3, len(actual.attributes))
        self.assertEqual(0x5e276611, actual.originating_time)
        self.assertEqual(1, actual.peer_index)
        self.assertEqual(28, actual.nbytes)


class TestRibTable(unittest.TestCase):
    CT = TN.RibTable

    def test_init(self):
        actual = self.CT( 6, 10)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual(actual.address_family, 6)
        self.assertEqual(actual.nbytes, 10)


class TestRibTableIPV6Unicast(unittest.TestCase):
    CT = TN.RibTableIPv6Unicast

    def test_unpack_from(self):
        packed = b"\x00\x00\x00\x00"\
                 b"\x18\x00\x00\x00"\
                 b"\x00\x01"\
                 b"\x00\x01\x5e\x27\x66\x11\x00\x14"\
                 b"\x40\x01\x01\x02\x40\x02\x06\x02\x01\x00\x00\xfe\x4c\x40\x05\x04\x00\x00\x00\x01"
        actual = self.CT.unpack_from(4, packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertIsInstance(actual.prefix, TN.MRTPrefix)
        self.assertEqual(0, actual.sequence_number)
        self.assertEqual(1, actual.length)
        self.assertEqual(28, actual.nbytes)


class TestMRTSection(unittest.TestCase):
    CT = TN.MRTSection

    def test_unpack_from(self):
        packed = b"\x5e\x27\x66\x4b\x00\x0d\x00\x01\x00\x00\x00\x35\x0a\x00\x00\x01" \
                 b"\x00\x07\x6d\x61\x73\x74\x65\x72\x36\x00\x02\x03\x00\x00\x00\x00" \
                 b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                 b"\x00\x00\x00\x00\x02\x14\x00\x00\x00\xac\x15\x00\x07\x00\x00\xfe" \
                 b"\x4c\x5e\x27\x66\x4b\x00\x0d\x00\x04\x00\x00\x00\x26\x00\x00\x00" \
                 b"\x00\x18\x00\x00\x00\x00\x01\x00\x01\x5e\x27\x66\x11\x00\x14\x40" \
                 b"\x01\x01\x02\x40\x02\x06\x02\x01\x00\x00\xfe\x4c\x00\x05\x04\x00" \
                 b"\x00\x00\x64\x5e\x27\x66\x88"
        actual = self.CT.unpack_from(packed, 0, None)
        self.assertIsInstance(actual, self.CT)
        self.assertIsInstance(actual.header, df.mrtanalysis.structure.MRTHeader)
        self.assertEqual((13, 1), actual.entry_type)


class TestMRTDump(unittest.TestCase):
    CT = TN.MRTDump

    def test_unpack_from(self):
        packed = b"\x5e\x27\x66\x4b\x00\x0d\x00\x01\x00\x00\x00\x35\x0a\x00\x00\x01" \
                 b"\x00\x07\x6d\x61\x73\x74\x65\x72\x36\x00\x02\x03\x00\x00\x00\x00" \
                 b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                 b"\x00\x00\x00\x00\x02\x14\x00\x00\x00\xac\x15\x00\x07\x00\x00\xfe" \
                 b"\x4c\x5e\x27\x66\x4b\x00\x0d\x00\x04\x00\x00\x00\x26\x00\x00\x00" \
                 b"\x00\x18\x00\x00\x00\x00\x01\x00\x01\x5e\x27\x66\x11\x00\x14\x40" \
                 b"\x01\x01\x02\x40\x02\x06\x02\x01\x00\x00\xfe\x4c\x00\x05\x04\x00" \
                 b"\x00\x00\x64\x5e\x27\x66\x88\x00\x0d\x00\x01\x00\x00\x00\x35\x0a" \
                 b"\x00\x00\x01\x00\x07\x6d\x61\x73\x74\x65\x72\x36\x00\x02\x03\x00" \
                 b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                 b"\x00\x00\x00\x00\x00\x00\x00\x02\x14\x00\x00\x00\xac\x15\x00\x07" \
                 b"\x00\x00\xfe\x4c"

        actual = self.CT.unpack_from(packed, 0)
        self.assertIsInstance(actual, self.CT)
        self.assertEqual( len(packed), actual.nbytes)
        self.assertEqual(2, len(actual))
        self.assertEqual((13,1), actual.sections[0].entry_type)
        self.assertEqual((13,4), actual.sections[1].entry_type)



if __name__ == "__main__":
    unittest.main()
