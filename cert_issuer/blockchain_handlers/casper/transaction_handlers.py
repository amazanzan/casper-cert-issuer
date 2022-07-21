import logging

from pycoin.serialize import b2h

from cert_issuer.errors import InsufficientFundsError
from cert_issuer.blockchain_handlers.ethereum import tx_utils
from cert_issuer.blockchain_handlers.ethereum.transaction_handlers import EthereumTransactionCreator
from cert_issuer.models import TransactionHandler
from cert_issuer.signer import FinalizableSigner


class CasperTransactionHandler(TransactionHandler):
    def __init__(self, connector, tx_cost_constants, secret_manager, issuing_address, prepared_inputs=None,
                 transaction_creator=EthereumTransactionCreator()):
        self.connector = connector
        self.tx_cost_constants = tx_cost_constants
        self.secret_manager = secret_manager
        self.issuing_address = issuing_address
        # input transactions are not needed for Ether or Casper
        self.prepared_inputs = prepared_inputs
        self.transaction_creator = transaction_creator

    def ensure_balance(self):
        self.balance = self.connector.get_balance(self.issuing_address)

        transaction_cost = self.tx_cost_constants.get_total_cost()
        recommended_gas_price = self.tx_cost_constants.get_recommended_gas_price()
        minimum_transfer_amount = self.tx_cost_constants.get_minimum_transfer_amount()
        logging.info('gas price will be %i motes and amount transferred will be %f CSPR', 
                      recommended_gas_price, minimum_transfer_amount / 1e9)

        if transaction_cost > self.balance:
            error_message = 'Please add {} CSPR to the address {}'.format(
                (transaction_cost - self.balance) / 1e9, self.issuing_address)
            logging.error(error_message)
            raise InsufficientFundsError(error_message)

    def issue_transaction(self, blockchain_bytes):
        eth_data_field = b2h(blockchain_bytes)
        path_to_secret = self.secret_manager.path_to_secret
        transaction_cost = self.tx_cost_constants.get_total_cost()
        txid = self.broadcast_transaction(eth_data_field, path_to_secret, transaction_cost)
        return txid

    def create_transaction(self, blockchain_bytes):
        if self.balance:
            # it is assumed here that the address has sufficient funds, as the ensure_balance has just been checked
            nonce = self.connector.get_address_nonce(self.issuing_address)
            # Transactions in the first iteration will be send to burn address
            toaddress = '0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead'
            tx = self.transaction_creator.create_transaction(self.tx_cost_constants, self.issuing_address, nonce,
                                                             toaddress, blockchain_bytes)

            prepared_tx = tx
            return prepared_tx
        else:
            raise InsufficientFundsError('Not sufficient ether to spend at: %s', self.issuing_address)

    def sign_transaction(self, prepared_tx):
        # stubbed from BitcoinTransactionHandler
        with FinalizableSigner(self.secret_manager) as signer:
            signed_tx = signer.sign_transaction(prepared_tx)

        logging.info('signed Ethereum trx = %s', signed_tx)
        return signed_tx

    def broadcast_transaction(self, eth_data_field, path_to_secret, transaction_cost):
        txid = self.connector.broadcast_tx(eth_data_field, path_to_secret, transaction_cost)
        return txid

    def verify_transaction(self, signed_tx, eth_data_field):
        tx_utils.verify_eth_transaction(signed_tx, eth_data_field)
