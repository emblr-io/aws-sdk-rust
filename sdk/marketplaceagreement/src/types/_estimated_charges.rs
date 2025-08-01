// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Estimated cost of the agreement.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EstimatedCharges {
    /// <p>Defines the currency code for the charge.</p>
    pub currency_code: ::std::option::Option<::std::string::String>,
    /// <p>The total known amount customer has to pay across the lifecycle of the agreement.</p><note>
    /// <p>This is the total contract value if accepted terms contain <code>ConfigurableUpfrontPricingTerm</code> or <code>FixedUpfrontPricingTerm</code>. In the case of pure contract pricing, this will be the total value of the contract. In the case of contracts with consumption pricing, this will only include the committed value and not include any overages that occur.</p>
    /// <p>If the accepted terms contain <code>PaymentScheduleTerm</code>, it will be the total payment schedule amount. This occurs when flexible payment schedule is used, and is the sum of all invoice charges in the payment schedule.</p>
    /// <p>In case a customer has amended an agreement, by purchasing more units of any dimension, this will include both the original cost as well as the added cost incurred due to addition of new units.</p>
    /// <p>This is <code>0</code> if the accepted terms contain <code>UsageBasedPricingTerm</code> without <code>ConfigurableUpfrontPricingTerm</code> or <code>RecurringPaymentTerm</code>. This occurs for usage-based pricing (such as SaaS metered or AMI/container hourly or monthly), because the exact usage is not known upfront.</p>
    /// </note>
    pub agreement_value: ::std::option::Option<::std::string::String>,
}
impl EstimatedCharges {
    /// <p>Defines the currency code for the charge.</p>
    pub fn currency_code(&self) -> ::std::option::Option<&str> {
        self.currency_code.as_deref()
    }
    /// <p>The total known amount customer has to pay across the lifecycle of the agreement.</p><note>
    /// <p>This is the total contract value if accepted terms contain <code>ConfigurableUpfrontPricingTerm</code> or <code>FixedUpfrontPricingTerm</code>. In the case of pure contract pricing, this will be the total value of the contract. In the case of contracts with consumption pricing, this will only include the committed value and not include any overages that occur.</p>
    /// <p>If the accepted terms contain <code>PaymentScheduleTerm</code>, it will be the total payment schedule amount. This occurs when flexible payment schedule is used, and is the sum of all invoice charges in the payment schedule.</p>
    /// <p>In case a customer has amended an agreement, by purchasing more units of any dimension, this will include both the original cost as well as the added cost incurred due to addition of new units.</p>
    /// <p>This is <code>0</code> if the accepted terms contain <code>UsageBasedPricingTerm</code> without <code>ConfigurableUpfrontPricingTerm</code> or <code>RecurringPaymentTerm</code>. This occurs for usage-based pricing (such as SaaS metered or AMI/container hourly or monthly), because the exact usage is not known upfront.</p>
    /// </note>
    pub fn agreement_value(&self) -> ::std::option::Option<&str> {
        self.agreement_value.as_deref()
    }
}
impl EstimatedCharges {
    /// Creates a new builder-style object to manufacture [`EstimatedCharges`](crate::types::EstimatedCharges).
    pub fn builder() -> crate::types::builders::EstimatedChargesBuilder {
        crate::types::builders::EstimatedChargesBuilder::default()
    }
}

/// A builder for [`EstimatedCharges`](crate::types::EstimatedCharges).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EstimatedChargesBuilder {
    pub(crate) currency_code: ::std::option::Option<::std::string::String>,
    pub(crate) agreement_value: ::std::option::Option<::std::string::String>,
}
impl EstimatedChargesBuilder {
    /// <p>Defines the currency code for the charge.</p>
    pub fn currency_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.currency_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Defines the currency code for the charge.</p>
    pub fn set_currency_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.currency_code = input;
        self
    }
    /// <p>Defines the currency code for the charge.</p>
    pub fn get_currency_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.currency_code
    }
    /// <p>The total known amount customer has to pay across the lifecycle of the agreement.</p><note>
    /// <p>This is the total contract value if accepted terms contain <code>ConfigurableUpfrontPricingTerm</code> or <code>FixedUpfrontPricingTerm</code>. In the case of pure contract pricing, this will be the total value of the contract. In the case of contracts with consumption pricing, this will only include the committed value and not include any overages that occur.</p>
    /// <p>If the accepted terms contain <code>PaymentScheduleTerm</code>, it will be the total payment schedule amount. This occurs when flexible payment schedule is used, and is the sum of all invoice charges in the payment schedule.</p>
    /// <p>In case a customer has amended an agreement, by purchasing more units of any dimension, this will include both the original cost as well as the added cost incurred due to addition of new units.</p>
    /// <p>This is <code>0</code> if the accepted terms contain <code>UsageBasedPricingTerm</code> without <code>ConfigurableUpfrontPricingTerm</code> or <code>RecurringPaymentTerm</code>. This occurs for usage-based pricing (such as SaaS metered or AMI/container hourly or monthly), because the exact usage is not known upfront.</p>
    /// </note>
    pub fn agreement_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agreement_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The total known amount customer has to pay across the lifecycle of the agreement.</p><note>
    /// <p>This is the total contract value if accepted terms contain <code>ConfigurableUpfrontPricingTerm</code> or <code>FixedUpfrontPricingTerm</code>. In the case of pure contract pricing, this will be the total value of the contract. In the case of contracts with consumption pricing, this will only include the committed value and not include any overages that occur.</p>
    /// <p>If the accepted terms contain <code>PaymentScheduleTerm</code>, it will be the total payment schedule amount. This occurs when flexible payment schedule is used, and is the sum of all invoice charges in the payment schedule.</p>
    /// <p>In case a customer has amended an agreement, by purchasing more units of any dimension, this will include both the original cost as well as the added cost incurred due to addition of new units.</p>
    /// <p>This is <code>0</code> if the accepted terms contain <code>UsageBasedPricingTerm</code> without <code>ConfigurableUpfrontPricingTerm</code> or <code>RecurringPaymentTerm</code>. This occurs for usage-based pricing (such as SaaS metered or AMI/container hourly or monthly), because the exact usage is not known upfront.</p>
    /// </note>
    pub fn set_agreement_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agreement_value = input;
        self
    }
    /// <p>The total known amount customer has to pay across the lifecycle of the agreement.</p><note>
    /// <p>This is the total contract value if accepted terms contain <code>ConfigurableUpfrontPricingTerm</code> or <code>FixedUpfrontPricingTerm</code>. In the case of pure contract pricing, this will be the total value of the contract. In the case of contracts with consumption pricing, this will only include the committed value and not include any overages that occur.</p>
    /// <p>If the accepted terms contain <code>PaymentScheduleTerm</code>, it will be the total payment schedule amount. This occurs when flexible payment schedule is used, and is the sum of all invoice charges in the payment schedule.</p>
    /// <p>In case a customer has amended an agreement, by purchasing more units of any dimension, this will include both the original cost as well as the added cost incurred due to addition of new units.</p>
    /// <p>This is <code>0</code> if the accepted terms contain <code>UsageBasedPricingTerm</code> without <code>ConfigurableUpfrontPricingTerm</code> or <code>RecurringPaymentTerm</code>. This occurs for usage-based pricing (such as SaaS metered or AMI/container hourly or monthly), because the exact usage is not known upfront.</p>
    /// </note>
    pub fn get_agreement_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.agreement_value
    }
    /// Consumes the builder and constructs a [`EstimatedCharges`](crate::types::EstimatedCharges).
    pub fn build(self) -> crate::types::EstimatedCharges {
        crate::types::EstimatedCharges {
            currency_code: self.currency_code,
            agreement_value: self.agreement_value,
        }
    }
}
