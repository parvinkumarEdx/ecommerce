from django.conf import settings

from django.conf.urls import include, url

from ecommerce.extensions.payment.views import PaymentFailedView, SDNFailure, cybersource, paypal, stripe, razorpay

CYBERSOURCE_APPLE_PAY_URLS = [
    url(r'^authorize/$', cybersource.CybersourceApplePayAuthorizationView.as_view(), name='authorize'),
    url(r'^start-session/$', cybersource.ApplePayStartSessionView.as_view(), name='start_session'),
]
CYBERSOURCE_URLS = [
    url(r'^apple-pay/', include((CYBERSOURCE_APPLE_PAY_URLS, 'apple_pay'))),
    url(r'^authorize/$', cybersource.CybersourceAuthorizeAPIView.as_view(), name='authorize'),
]

PAYPAL_URLS = [
    url(r'^execute/$', paypal.PaypalPaymentExecutionView.as_view(), name='execute'),
    url(r'^profiles/$', paypal.PaypalProfileAdminView.as_view(), name='profiles'),
]

SDN_URLS = [
    url(r'^failure/$', SDNFailure.as_view(), name='failure'),
]

STRIPE_URLS = [
    url(r'^submit/$', stripe.StripeSubmitView.as_view(), name='submit'),
]

RAZORPAY_URLS = [
    url(r'^execution/$', razorpay.RazorpayExecutionView.as_view(), name='razorpay-execution'),
    url(r'^cancel/$', razorpay.RazorpayCancelView.as_view(), name='razorpay-cancel'),
]

urlpatterns = [
    url(r'^cybersource/', include((CYBERSOURCE_URLS, 'cybersource'))),
    url(r'^error/$', PaymentFailedView.as_view(), name='payment_error'),
    url(r'^paypal/', include((PAYPAL_URLS, 'paypal'))),
    url(r'^sdn/', include((SDN_URLS, 'sdn'))),
    url(r'^stripe/', include((STRIPE_URLS, 'stripe'))),
    url(r'^razorpay/', include((RAZORPAY_URLS, 'razorpay'))),
]

for payment_processor_name, urls_module in settings.EXTRA_PAYMENT_PROCESSOR_URLS.items():	
    processor_url = url(r'^{}/'.format(payment_processor_name), include((urls_module, payment_processor_name)))	
    urlpatterns.append(processor_url)
