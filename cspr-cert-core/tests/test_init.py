import unittest

from cert_core import *


class TestInit(unittest.TestCase):
    def test_is_mainnet_address_true(self):
        is_mainnet = is_bitcoin_mainnet_address('1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v')
        self.assertTrue(is_mainnet)

    def test_is_mainnet_address_false(self):
        is_mainnet = is_bitcoin_mainnet_address('mjgZHpD1AzEixLgcnncod5df6CntYK4Jpi')
        self.assertFalse(is_mainnet)

    def test_blockchain_display_value_bitcoin(self):
        chain = BlockchainType.bitcoin
        self.assertEqual(chain.external_display_value, 'BTCOpReturn')

    def test_blockchain_display_value_ethereum(self):
        chain = BlockchainType.ethereum
        self.assertEqual(chain.external_display_value, 'ETHData')

    def test_blockchain_display_value_mock(self):
        chain = BlockchainType.mock
        self.assertEqual(chain.external_display_value, 'Mock')

    def test_blockchain_display_value_casper(self):
        chain = BlockchainType.casper
        self.assertEqual(chain.external_display_value, 'CSPRData')

    def test_parse_from_chain_string_bitcoin_mainnet(self):
        chain = Chain.parse_from_chain('bitcoin_mainnet')
        self.assertEqual(chain, Chain.bitcoin_mainnet)

    def test_parse_from_chain_string_bitcoin_testnet(self):
        chain = Chain.parse_from_chain('bitcoin_testnet')
        self.assertEqual(chain, Chain.bitcoin_testnet)

    def test_parse_from_chain_string_bitcoin_regtest(self):
        chain = Chain.parse_from_chain('bitcoin_regtest')
        self.assertEqual(chain, Chain.bitcoin_regtest)

    def test_parse_from_chain_string_ethereum_mainnet(self):
        chain = Chain.parse_from_chain('ethereum_mainnet')
        self.assertEqual(chain, Chain.ethereum_mainnet)

    def test_parse_from_chain_string_ethereum_ropsten(self):
        chain = Chain.parse_from_chain('ethereum_ropsten')
        self.assertEqual(chain, Chain.ethereum_ropsten)

    def test_parse_from_chain_string_mockchain(self):
        chain = Chain.parse_from_chain('mockchain')
        self.assertEqual(chain, Chain.mockchain)

    def test_parse_from_chain_string_casper_mainnet(self):
        chain = Chain.parse_from_chain('casper_mainnet')
        self.assertEqual(chain, Chain.casper_mainnet)

    def test_parse_from_chain_string_casper_testnet(self):
        chain = Chain.parse_from_chain('casper_testnet')
        self.assertEqual(chain, Chain.casper_testnet)

    def test_parse_from_external_display_value_bitcoin_mainnet(self):
        chain = Chain.parse_from_external_display_value('bitcoinMainnet')
        self.assertEqual(chain, Chain.bitcoin_mainnet)

    def test_parse_from_external_display_value_bitcoin_testnet(self):
        chain = Chain.parse_from_external_display_value('bitcoinTestnet')
        self.assertEqual(chain, Chain.bitcoin_testnet)

    def test_parse_from_external_display_value_bitcoin_regtest(self):
        chain = Chain.parse_from_external_display_value('bitcoinRegtest')
        self.assertEqual(chain, Chain.bitcoin_regtest)

    def test_parse_from_external_display_value_ethereum_mainnet(self):
        chain = Chain.parse_from_external_display_value('ethereumMainnet')
        self.assertEqual(chain, Chain.ethereum_mainnet)

    def test_parse_from_external_display_value_ethereum_ropsten(self):
        chain = Chain.parse_from_external_display_value('ethereumRopsten')
        self.assertEqual(chain, Chain.ethereum_ropsten)

    def test_parse_from_external_display_value_mockchain(self):
        chain = Chain.parse_from_external_display_value('mockchain')
        self.assertEqual(chain, Chain.mockchain)

    def test_parse_from_external_display_value_casper_mainnet(self):
        chain = Chain.parse_from_external_display_value('casperMainnet')
        self.assertEqual(chain, Chain.casper_mainnet)

    def test_parse_from_external_display_value_casper_testnet(self):
        chain = Chain.parse_from_external_display_value('casperTestnet')
        self.assertEqual(chain, Chain.casper_testnet)

    def test_bitcoin_chain_to_netcode_bitcoin_mainnet(self):
        netcode = chain_to_bitcoin_network(Chain.bitcoin_mainnet)
        self.assertEqual(netcode, 'mainnet')

    def test_bitcoin_chain_to_netcode_bitcoin_testnet(self):
        netcode = chain_to_bitcoin_network(Chain.bitcoin_testnet)
        self.assertEqual(netcode, 'testnet')

    def test_bitcoin_chain_to_netcode_bitcoin_testnet(self):
        netcode = chain_to_bitcoin_network(Chain.bitcoin_regtest)
        self.assertEqual(netcode, 'regtest')

    def test_bitcoin_chain_to_netcode_mocknet(self):
        """
        This should fail. Assert that we get an UnknownChainError
        :return:
        """
        try:
            chain_to_bitcoin_network(Chain.mockchain)
            self.assertTrue(False)
        except UnknownChainError:
            self.assertTrue(True)

    def test_bitcoin_chain_to_netcode_ethereum_mainnet(self):
        """
        This should fail. Assert that we get an UnknownChainError
        :return:
        """
        try:
            chain_to_bitcoin_network(Chain.ethereum_mainnet)
            self.assertTrue(False)
        except UnknownChainError:
            self.assertTrue(True)

    def test_bitcoin_chain_to_netcode_casper_mainnet(self):
        """
        This should fail. Assert that we get an UnknownChainError
        :return:
        """
        try:
            chain_to_bitcoin_network(Chain.casper_mainnet)
            self.assertTrue(False)
        except UnknownChainError:
            self.assertTrue(True)

    def test_blockcerts_versions_v2(self):
        v2_alpha = BlockcertVersion.V2_ALPHA
        self.assertEqual(v2_alpha, BlockcertVersion.V2_ALPHA)

if __name__ == '__main__':
    unittest.main()
