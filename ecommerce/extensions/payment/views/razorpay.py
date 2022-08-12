# Location = ecommerce/extensions/payment/views

import requests
import logging
import razorpay
import yaml
import hmac
import re
from hashlib import sha256
from collections import OrderedDict, defaultdict
from decimal import Decimal, InvalidOperation

from django.db import transaction
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.generic import TemplateView, View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required

from oscar.core.loading import get_class, get_model
from oscar.apps.payment.exceptions import GatewayError
from ecommerce.extensions.analytics.utils import audit_log, track_segment_event
from ecommerce.extensions.basket.utils import basket_add_organization_attribute
from ecommerce.extensions.checkout.mixins import EdxOrderPlacementMixin
from ecommerce.extensions.checkout.utils import get_receipt_page_url
from ecommerce.extensions.payment.views import BasePaymentSubmitView
from ecommerce.extensions.order.constants import PaymentEventTypeName

logger = logging.getLogger(__name__)

Applicator = get_class("offer.applicator", "Applicator")
BillingAddress = get_model("order", "BillingAddress")
Country = get_model("address", "Country")
NoShippingRequired = get_class("shipping.methods", "NoShippingRequired")
OrderTotalCalculator = get_class("checkout.calculators", "OrderTotalCalculator")
Basket = get_model("basket", "Basket")
PaymentEvent = get_model("order", "PaymentEvent")
PaymentEventType = get_model("order", "PaymentEventType")
Source = get_model("payment", "Source")
SourceType = get_model("payment", "SourceType")
PaymentProcessorResponse = get_model("payment", "PaymentProcessorResponse")


class RazorpayExecutionView(EdxOrderPlacementMixin, View):
    """Execute an approved Razorpay payment and place an order for paid products as appropriate."""

    # Disable atomicity for the view. Otherwise, we'd be unable to commit to the database
    # until the request had concluded; Django will refuse to commit when an atomic() block
    # is active, since that would break atomicity. Without an order present in the database
    # at the time fulfillment is attemped, asynchronous order fulfillment tasks will fail.
    @method_decorator(transaction.non_atomic_requests)
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        self._payment_events = None
        self.request = request
        self.configuration = self.configuration()
        self.api_key = self.configuration["api_key"]
        self.api_secret = self.configuration["api_secret"]
        self.basket = Basket.get_basket(request.user, request.site)
        return super(RazorpayExecutionView, self).dispatch(request, *args, **kwargs)

    def configuration(self):
        partner_short_code = self.request.site.siteconfiguration.partner.short_code
        return settings.PAYMENT_PROCESSOR_CONFIG[partner_short_code.lower()]["razorpay"]

    def post(self, request):
        params = request.POST.dict()
        self.receipt_url = get_receipt_page_url(
            site_configuration=request.site.siteconfiguration,
            order_number=self.basket.order_number,
            disable_back_button=True,
        )

        if params["amount"] != "0.00":
            # Fetches the Payment Details.
            payment_details = self.get_payment_details(params)
            # Updates the params dictionary.
            params.update(payment_details)
            # Converts Paise to Rupees. As Razorpay takes amount input in paise.
            params["amount"] = params["amount"] / 100
        valid_params = self.verify_signatures(params)
        result = self._payment_accepted(
            valid_params["amount"],
            valid_params["currency"],
            valid_params["status"],
        )
        if result.get("accepted", False):
            self.record_payment(self.basket, params)

        return redirect(self.receipt_url)

    def get_payment_details(self, params):
        """
        Gets the Payment Details.
        """

        url = "https://api.razorpay.com/v1/payments/" + params["pay_id"]
        resp = requests.get(url, data={}, auth=(self.api_key, self.api_secret))
        details = yaml.load(resp.content)
        return details

    def processor_hash(self, value):
        """
        Calculate the hex-encoded, SHA-256 hash used by Razorpay.
        Args:
            value (string): The value to encode.
        Returns:
            string
        """
        hash_obj = hmac.new(
            self.api_secret.encode("utf-8"), value.encode("utf-8"), sha256
        )
        return hash_obj.hexdigest()

    def verify_signatures(self, params):
        """
        Use the signature we receive in the GET back from Razorpay to verify
        the identity of the sender (Razorpay) and that the contents of the message
        have not been tampered with.
        Args:
            params (dictionary): The POST parameters we received from Razorpay.
        Returns:
            dict: Contains the parameters we will use elsewhere, converted to the
                appropriate types
        Raises:
            CCProcessorSignatureException: The calculated signature does not match
                the signature we received.
            CCProcessorDataException: The parameters we received from Razorpay were not valid
                (missing keys, wrong types)
        """

        # First see if the status is captured.
        # if not, then not all parameters will be passed back so we can't yet verify signatures
        if params.get("status") != u"captured":
            logger.exception(
                "An error occurred while processing the Razorpay payment for basket {}. Because payment status is {}".format(
                    self.basket.id, params.get("status")
                )
            )
            raise GatewayError

        # Validate the signature to ensure that the message is from Razorpay
        # and has not been tampered with.
        data = params["ord_id"] + "|" + params["pay_id"]
        returned_sig = params.get("sign", "")
        if self.processor_hash(data) != returned_sig:
            logger.exception(
                "An error occurred while processing the Razorpay payment for basket {}. Because invalid signature.".format(
                    self.basket.id
                )
            )
            raise GatewayError

        # Validate that we have the paramters we expect and can convert them
        # to the appropriate types.
        # Usually validating the signature is sufficient to validate that these
        # fields exist, but since we're relying on Razorpay to tell us
        # which fields they included in the signature, we need to be careful.
        valid_params = {}
        required_params = [
            ("currency", str),
            ("status", str),
            ("amount", Decimal),
        ]
        for key, key_type in required_params:
            if key not in params:
                logger.exception(
                    "The payment processor did not return a required parameter: {parameter}".format(
                        parameter=key
                    )
                )
                raise GatewayError
            try:
                valid_params[key] = key_type(params[key])
            except (ValueError, TypeError, InvalidOperation):
                logger.exception(
                    "The payment processor returned a badly-typed value {value} for parameter {parameter}.".format(
                        value=params[key], parameter=key
                    )
                )
                raise GatewayError

        return valid_params


    def _payment_accepted(self, auth_amount, currency, decision):
        """
        Check that Razorpay has accepted the payment.
        Args:
            order_num (int): The ID of the order associated with this payment.
            auth_amount (Decimal): The amount the user paid using Razorpay.
            currency (str): The currency code of the payment.
            decision (str): "ACCEPT" if the payment was accepted.
        Returns:
            dictionary of the form:
            {
                'accepted': bool,
                'amnt_charged': int,
                'currency': string,
            }
        """
        if decision == "captured":
            if currency.lower() == self.basket.currency.lower():
                return {
                    "accepted": True,
                    "amt_charged": auth_amount,
                    "currency": currency,
                }
            else:
                logger.exception(
                    "The amount charged by the processor {charged_amount} {charged_amount_currency} is different than the total cost of the order {total_cost} {total_cost_currency}.".format(
                        charged_amount=auth_amount,
                        charged_amount_currency=currency,
                        total_cost=self.basket.total_incl_tax,
                        total_cost_currency=self.basket.currency,
                    )
                )
                return {"accepted": False, "amt_charged": auth_amount, "currency": currency}
        else:
            return {"accepted": False, "amt_charged": auth_amount, "currency": currency}


    def add_payment_event(self, event):  # pylint: disable = arguments-differ
        """ Record a payment event for creation once the order is placed. """
        if self._payment_events is None:
            self._payment_events = []
        self._payment_events.append(event)

    def record_payment(self, basket, handled_processor_response):
        source_type, __ = SourceType.objects.get_or_create(name="razorpay")
        total = handled_processor_response.get('amount')
        reference = handled_processor_response.get('ord_id')
        source = Source(
            source_type=source_type,
            currency=handled_processor_response.get('currency'),
            amount_allocated=total,
            amount_debited=total,
            reference=reference,
            label="",
            card_type="",
        )
        event_type, __ = PaymentEventType.objects.get_or_create(
            name=PaymentEventTypeName.PAID
        )
        payment_event = PaymentEvent(
            event_type=event_type,
            amount=total,
            reference=reference,
            processor_name="razorpay",
        )
        # self.add_payment_source(source)
        self.add_payment_event(payment_event)
        audit_log(
            "payment_received",
            amount=payment_event.amount,
            basket_id=basket.id,
            currency=source.currency,
            processor_name=payment_event.processor_name,
            reference=payment_event.reference,
            user_id=basket.owner.id,
        )

        try:
            order = self.create_order(self.request, basket, billing_address=None)
        except Exception:  # pylint: disable=broad-except
            logger.exception(
                "An error occurred while processing the Razorpay payment for basket [%d].",
                basket.id,
            )
            return JsonResponse({}, status=400)

        self.handle_post_order(order)


class RazorpayCancelView(TemplateView):
    """
    Displays a cancellation message when the customer cancels checkout on the
    payment processor page.
    """

    template_name = "oscar/checkout/cancel_checkout.html"

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):  # pylint: disable=arguments-differ
        """
        Request needs to be csrf_exempt to handle POST back from external payment processor.
        """
        return super(RazorpayCancelView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):  # pylint: disable=unused-argument
        """
        Allow POST responses from payment processors and just render the cancel page..
        """
        context = self.get_context_data(**kwargs)
        return self.render_to_response(context)

    def get(self, request, *args, **kwargs):  # pylint: disable=unused-argument
        """
        Allow POST responses from payment processors and just render the cancel page..
        """
        context = self.get_context_data(**kwargs)
        return self.render_to_response(context)

    def get_context_data(self, **kwargs):
        context = super(RazorpayCancelView, self).get_context_data(**kwargs)
        context.update(
            {
                "payment_support_email": self.request.site.siteconfiguration.payment_support_email,
            }
        )
