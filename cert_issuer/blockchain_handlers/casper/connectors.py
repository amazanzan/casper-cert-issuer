import logging
import time

from cert_core import Chain
from cert_issuer.models import ServiceProviderConnector
from cert_issuer.errors import BroadcastError

import typing
import pycspr
from pycspr import NodeClient
from pycspr import NodeConnection
from pycspr.crypto import KeyAlgorithm
from pycspr.types import PrivateKey
from pycspr.types import Deploy
from pycspr.types import PublicKey
from pycspr.factory import create_public_key_from_account_key

BROADCAST_RETRY_INTERVAL = 30
MAX_BROADCAST_ATTEMPTS = 3


class CasperServiceProviderConnector(ServiceProviderConnector):
    # param local_node indicates if a local node is running or if the tx should be broadcast to external providers
    def __init__(
            self,
            casper_chain,
            app_config,
            local_node=False):
        self.casper_chain = casper_chain
        self.target_address = app_config.target_address

        self.local_node = local_node

        # initialize connectors
        self.connectors = {}

        # Configure Casper mainnet connectors
        cspr_provider_list = []
        if app_config.casper_rpc_ip_address:
            self.casper_rpc_ip_address = app_config.casper_rpc_ip_address
            cspr_provider_list.append(CasperRPCProvider(self.target_address, self.casper_rpc_ip_address, True))
        self.connectors[Chain.casper_mainnet] = cspr_provider_list

        # Configure Casper testnet connectors
        csprtest_provider_list = []
        if app_config.caspertest_rpc_ip_address:
            self.caspertest_rpc_ip_address = app_config.caspertest_rpc_ip_address
            csprtest_provider_list.append(CasperRPCProvider(self.target_address, self.caspertest_rpc_ip_address, False))
        self.connectors[Chain.casper_testnet] = csprtest_provider_list

    def get_providers_for_chain(self, chain, local_node=False):
        return self.connectors[chain]

    def get_balance(self, address):
        for m in self.get_providers_for_chain(self.casper_chain, self.local_node):
            try:
                logging.debug('m=%s', m)
                balance = m.get_balance(address)
                return balance
            except Exception as e:
                logging.warning(e)
                pass
        return 0

    def broadcast_tx(self, eth_data_field, path_to_secret, transaction_cost):

        last_exception = None
        final_tx_id = None

        # Broadcast to all available api's
        for attempt_number in range(0, MAX_BROADCAST_ATTEMPTS):
            for m in self.get_providers_for_chain(self.casper_chain, self.local_node):
                try:
                    logging.debug('m=%s', m)
                    txid = m.broadcast_tx(eth_data_field, path_to_secret, transaction_cost)
                    if (txid):
                        logging.info('Broadcasting succeeded with method_provider=%s, txid=%s', str(m), txid)
                        if final_tx_id and final_tx_id != txid:
                            logging.error(
                                'This should never happen; fail and investigate if it does. Got conflicting tx_ids=%s and %s. Hextx=%s',
                                final_tx_id, txid, tx.as_hex())
                            raise Exception('Got conflicting tx_ids.')
                        final_tx_id = txid
                    return txid
                except Exception as e:
                    logging.warning('Caught exception trying provider %s. Trying another. Exception=%s',
                                    str(m), e)
                    last_exception = e

            # At least 1 provider succeeded, so return
            if final_tx_id:
                return final_tx_id
            else:
                logging.warning('Broadcasting failed. Waiting before retrying. This is attempt number %d',
                                attempt_number)
                time.sleep(BROADCAST_RETRY_INTERVAL)

        ##in case of failure:
        logging.error('Failed broadcasting through all providers')
        logging.error(last_exception, exc_info=True)
        raise BroadcastError(last_exception)


def get_counter_parties(target_address, path_to_secret) -> typing.Tuple[PrivateKey, PublicKey]:
    """Returns the 2 counter-parties participating in the transfer.

    """
    # cp1 = pycspr.parse_private_key(path_to_secret, KeyAlgorithm.ED25519.name)
    cp1 = pycspr.parse_private_key(path_to_secret, KeyAlgorithm.SECP256K1.name)

    cp2_bytes = bytes.fromhex(target_address)
    cp2 = create_public_key_from_account_key(cp2_bytes)

    return cp1, cp2


def get_deploy(cp1: PrivateKey, cp2: PublicKey, is_mainnet: bool, bc_hash: str, transaction_cost: int) -> Deploy:
    """Returns transfer deploy to be dispatched to a node.

    """
    # Set standard deploy parameters.
    deploy_params = pycspr.create_deploy_parameters(
      account=cp1, 
      chain_name="casper-net-1" if is_mainnet else "casper-test", 
      )

    # Set deploy.
    deploy = pycspr.create_transfer(
        params=deploy_params,
        amount=transaction_cost,
        bc_hash="0x" + bc_hash,
        target=cp2.account_key,
        # correlation_id=random.randint(1, 1e6)
        )

    return deploy


class CasperRPCProvider(object):
    def __init__(self, target_address, casper_rpc_ip_address, is_mainnet):
        self.target_address = target_address
        self.casper_rpc_ip_address = casper_rpc_ip_address
        self.is_mainnet = is_mainnet

    def broadcast_tx(self, eth_data_field, path_to_secret, transaction_cost):
        logging.info('Broadcasting transaction with CasperRPCProvider')

        # Set node client.
        client = NodeClient(NodeConnection(host=self.casper_rpc_ip_address))

        # Set counter-parties.
        cp1, cp2 = get_counter_parties(self.target_address, path_to_secret)

        # Set deploy.
        deploy: Deploy = get_deploy(cp1, cp2, self.is_mainnet, eth_data_field, transaction_cost)

        # raise(Exception("Dry run. Halting issuing."))

        # Approve deploy.
        deploy.approve(cp1)

        # Dispatch deploy to a node.
        client.send_deploy(deploy)
        txid = deploy.hash.hex()

        return txid

    def get_balance(self, address):
        """
        Returns the balance in motes.
        """
        logging.info('Getting balance with CasperRPCProvider')

        # Set node client.
        client = NodeClient(NodeConnection(host=self.casper_rpc_ip_address))

        # get_state_root_hash - required for global state related queries.
        state_root_hash: bytes = client.get_state_root_hash()
        assert isinstance(state_root_hash, bytes)

        # get_account_info.
        account_info: dict = client.get_account_info(address)
        assert isinstance(account_info, dict)
        account_main_purse = account_info['main_purse']

        # get_account_balance.
        account_balance: int = client.get_account_balance(account_main_purse, state_root_hash)
        assert isinstance(account_balance, int)
        logging.info(f"ACCOUNT BALANCE FOR {address} = {account_balance}")

        return account_balance
