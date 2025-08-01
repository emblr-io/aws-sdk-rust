// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides a summary of commitment-related information for a bill estimate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BillEstimateCommitmentSummary {
    /// <p>The unique identifier of the commitment.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The type of purchase agreement (e.g., Reserved Instance, Savings Plan).</p>
    pub purchase_agreement_type: ::std::option::Option<crate::types::PurchaseAgreementType>,
    /// <p>The identifier of the specific offering associated with this commitment.</p>
    pub offering_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID associated with this commitment.</p>
    pub usage_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services region associated with this commitment.</p>
    pub region: ::std::option::Option<::std::string::String>,
    /// <p>The length of the commitment term.</p>
    pub term_length: ::std::option::Option<::std::string::String>,
    /// <p>The payment option chosen for this commitment (e.g., All Upfront, Partial Upfront, No Upfront).</p>
    pub payment_option: ::std::option::Option<::std::string::String>,
    /// <p>The upfront payment amount for this commitment, if applicable.</p>
    pub upfront_payment: ::std::option::Option<crate::types::CostAmount>,
    /// <p>The monthly payment amount for this commitment, if applicable.</p>
    pub monthly_payment: ::std::option::Option<crate::types::CostAmount>,
}
impl BillEstimateCommitmentSummary {
    /// <p>The unique identifier of the commitment.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The type of purchase agreement (e.g., Reserved Instance, Savings Plan).</p>
    pub fn purchase_agreement_type(&self) -> ::std::option::Option<&crate::types::PurchaseAgreementType> {
        self.purchase_agreement_type.as_ref()
    }
    /// <p>The identifier of the specific offering associated with this commitment.</p>
    pub fn offering_id(&self) -> ::std::option::Option<&str> {
        self.offering_id.as_deref()
    }
    /// <p>The Amazon Web Services account ID associated with this commitment.</p>
    pub fn usage_account_id(&self) -> ::std::option::Option<&str> {
        self.usage_account_id.as_deref()
    }
    /// <p>The Amazon Web Services region associated with this commitment.</p>
    pub fn region(&self) -> ::std::option::Option<&str> {
        self.region.as_deref()
    }
    /// <p>The length of the commitment term.</p>
    pub fn term_length(&self) -> ::std::option::Option<&str> {
        self.term_length.as_deref()
    }
    /// <p>The payment option chosen for this commitment (e.g., All Upfront, Partial Upfront, No Upfront).</p>
    pub fn payment_option(&self) -> ::std::option::Option<&str> {
        self.payment_option.as_deref()
    }
    /// <p>The upfront payment amount for this commitment, if applicable.</p>
    pub fn upfront_payment(&self) -> ::std::option::Option<&crate::types::CostAmount> {
        self.upfront_payment.as_ref()
    }
    /// <p>The monthly payment amount for this commitment, if applicable.</p>
    pub fn monthly_payment(&self) -> ::std::option::Option<&crate::types::CostAmount> {
        self.monthly_payment.as_ref()
    }
}
impl BillEstimateCommitmentSummary {
    /// Creates a new builder-style object to manufacture [`BillEstimateCommitmentSummary`](crate::types::BillEstimateCommitmentSummary).
    pub fn builder() -> crate::types::builders::BillEstimateCommitmentSummaryBuilder {
        crate::types::builders::BillEstimateCommitmentSummaryBuilder::default()
    }
}

/// A builder for [`BillEstimateCommitmentSummary`](crate::types::BillEstimateCommitmentSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BillEstimateCommitmentSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) purchase_agreement_type: ::std::option::Option<crate::types::PurchaseAgreementType>,
    pub(crate) offering_id: ::std::option::Option<::std::string::String>,
    pub(crate) usage_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) region: ::std::option::Option<::std::string::String>,
    pub(crate) term_length: ::std::option::Option<::std::string::String>,
    pub(crate) payment_option: ::std::option::Option<::std::string::String>,
    pub(crate) upfront_payment: ::std::option::Option<crate::types::CostAmount>,
    pub(crate) monthly_payment: ::std::option::Option<crate::types::CostAmount>,
}
impl BillEstimateCommitmentSummaryBuilder {
    /// <p>The unique identifier of the commitment.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the commitment.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier of the commitment.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The type of purchase agreement (e.g., Reserved Instance, Savings Plan).</p>
    pub fn purchase_agreement_type(mut self, input: crate::types::PurchaseAgreementType) -> Self {
        self.purchase_agreement_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of purchase agreement (e.g., Reserved Instance, Savings Plan).</p>
    pub fn set_purchase_agreement_type(mut self, input: ::std::option::Option<crate::types::PurchaseAgreementType>) -> Self {
        self.purchase_agreement_type = input;
        self
    }
    /// <p>The type of purchase agreement (e.g., Reserved Instance, Savings Plan).</p>
    pub fn get_purchase_agreement_type(&self) -> &::std::option::Option<crate::types::PurchaseAgreementType> {
        &self.purchase_agreement_type
    }
    /// <p>The identifier of the specific offering associated with this commitment.</p>
    pub fn offering_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.offering_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the specific offering associated with this commitment.</p>
    pub fn set_offering_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.offering_id = input;
        self
    }
    /// <p>The identifier of the specific offering associated with this commitment.</p>
    pub fn get_offering_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.offering_id
    }
    /// <p>The Amazon Web Services account ID associated with this commitment.</p>
    pub fn usage_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID associated with this commitment.</p>
    pub fn set_usage_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID associated with this commitment.</p>
    pub fn get_usage_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage_account_id
    }
    /// <p>The Amazon Web Services region associated with this commitment.</p>
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services region associated with this commitment.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>The Amazon Web Services region associated with this commitment.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// <p>The length of the commitment term.</p>
    pub fn term_length(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.term_length = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The length of the commitment term.</p>
    pub fn set_term_length(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.term_length = input;
        self
    }
    /// <p>The length of the commitment term.</p>
    pub fn get_term_length(&self) -> &::std::option::Option<::std::string::String> {
        &self.term_length
    }
    /// <p>The payment option chosen for this commitment (e.g., All Upfront, Partial Upfront, No Upfront).</p>
    pub fn payment_option(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.payment_option = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The payment option chosen for this commitment (e.g., All Upfront, Partial Upfront, No Upfront).</p>
    pub fn set_payment_option(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.payment_option = input;
        self
    }
    /// <p>The payment option chosen for this commitment (e.g., All Upfront, Partial Upfront, No Upfront).</p>
    pub fn get_payment_option(&self) -> &::std::option::Option<::std::string::String> {
        &self.payment_option
    }
    /// <p>The upfront payment amount for this commitment, if applicable.</p>
    pub fn upfront_payment(mut self, input: crate::types::CostAmount) -> Self {
        self.upfront_payment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The upfront payment amount for this commitment, if applicable.</p>
    pub fn set_upfront_payment(mut self, input: ::std::option::Option<crate::types::CostAmount>) -> Self {
        self.upfront_payment = input;
        self
    }
    /// <p>The upfront payment amount for this commitment, if applicable.</p>
    pub fn get_upfront_payment(&self) -> &::std::option::Option<crate::types::CostAmount> {
        &self.upfront_payment
    }
    /// <p>The monthly payment amount for this commitment, if applicable.</p>
    pub fn monthly_payment(mut self, input: crate::types::CostAmount) -> Self {
        self.monthly_payment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The monthly payment amount for this commitment, if applicable.</p>
    pub fn set_monthly_payment(mut self, input: ::std::option::Option<crate::types::CostAmount>) -> Self {
        self.monthly_payment = input;
        self
    }
    /// <p>The monthly payment amount for this commitment, if applicable.</p>
    pub fn get_monthly_payment(&self) -> &::std::option::Option<crate::types::CostAmount> {
        &self.monthly_payment
    }
    /// Consumes the builder and constructs a [`BillEstimateCommitmentSummary`](crate::types::BillEstimateCommitmentSummary).
    pub fn build(self) -> crate::types::BillEstimateCommitmentSummary {
        crate::types::BillEstimateCommitmentSummary {
            id: self.id,
            purchase_agreement_type: self.purchase_agreement_type,
            offering_id: self.offering_id,
            usage_account_id: self.usage_account_id,
            region: self.region,
            term_length: self.term_length,
            payment_option: self.payment_option,
            upfront_payment: self.upfront_payment,
            monthly_payment: self.monthly_payment,
        }
    }
}
