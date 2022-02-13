import logging
import os

from cert_core import BlockchainType
from cert_core import UnknownChainError

from cert_issuer.certificate_handlers import CertificateBatchHandler, CertificateV2Handler
from cert_issuer.blockchain_handlers.ethereum.signer import EthereumSigner
from cert_issuer.merkle_tree_generator import MerkleTreeGenerator
from cert_issuer.signer import FileSecretManager

from cert_issuer.blockchain_handlers.casper.connectors import CasperServiceProviderConnector
from cert_issuer.blockchain_handlers.casper.transaction_handlers import CasperTransactionHandler

DEFAULT_GAS_PRICE = 1
MIN_TRANSFER_AMOUNT_MOTES = 2.5e9


class CasperTransactionCostConstants(object):
    def __init__(self, recommended_gas_price=1):
        self.recommended_gas_price = DEFAULT_GAS_PRICE
        self.minimum_transfer_amount = MIN_TRANSFER_AMOUNT_MOTES
        self.total_cost = int(MIN_TRANSFER_AMOUNT_MOTES + DEFAULT_GAS_PRICE)
        logging.info('Set cost constants to recommended_gas_price=%i motes and minimum_transfer_amount=%i motes', 
                      self.recommended_gas_price, self.minimum_transfer_amount)

    def get_recommended_gas_price(self):
        return self.recommended_gas_price

    def get_minimum_transfer_amount(self):
        return self.minimum_transfer_amount

    def get_total_cost(self):
        return self.total_cost


def initialize_signer(app_config):
    path_to_secret = os.path.join(app_config.usb_name, app_config.key_file)

    if app_config.chain.blockchain_type == BlockchainType.casper:
        signer = EthereumSigner(ethereum_chain=app_config.chain)
    else:
        raise UnknownChainError(app_config.chain)
    secret_manager = FileSecretManager(signer=signer, path_to_secret=path_to_secret,
                                       safe_mode=app_config.safe_mode, issuing_address=app_config.issuing_address)
    return secret_manager


def instantiate_blockchain_handlers(app_config):
    issuing_address = app_config.issuing_address
    chain = app_config.chain
    secret_manager = initialize_signer(app_config)
    certificate_batch_handler = CertificateBatchHandler(secret_manager=secret_manager,
                                                        certificate_handler=CertificateV2Handler(),
                                                        merkle_tree=MerkleTreeGenerator())

    cost_constants = CasperTransactionCostConstants(app_config.gas_price)
    connector = CasperServiceProviderConnector(chain, app_config)
    transaction_handler = CasperTransactionHandler(connector, cost_constants, secret_manager,
                                                    issuing_address=issuing_address)

    return certificate_batch_handler, transaction_handler, connector
