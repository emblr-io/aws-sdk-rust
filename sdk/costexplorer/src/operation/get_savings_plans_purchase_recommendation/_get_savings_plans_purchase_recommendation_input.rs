// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSavingsPlansPurchaseRecommendationInput {
    /// <p>The Savings Plans recommendation type that's requested.</p>
    pub savings_plans_type: ::std::option::Option<crate::types::SupportedSavingsPlansType>,
    /// <p>The savings plan recommendation term that's used to generate these recommendations.</p>
    pub term_in_years: ::std::option::Option<crate::types::TermInYears>,
    /// <p>The payment option that's used to generate these recommendations.</p>
    pub payment_option: ::std::option::Option<crate::types::PaymentOption>,
    /// <p>The account scope that you want your recommendations for. Amazon Web Services calculates recommendations including the management account and member accounts if the value is set to <code>PAYER</code>. If the value is <code>LINKED</code>, recommendations are calculated for individual member accounts only.</p>
    pub account_scope: ::std::option::Option<crate::types::AccountScope>,
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    /// <p>The number of recommendations that you want returned in a single response object.</p>
    pub page_size: ::std::option::Option<i32>,
    /// <p>The lookback period that's used to generate the recommendation.</p>
    pub lookback_period_in_days: ::std::option::Option<crate::types::LookbackPeriodInDays>,
    /// <p>You can filter your recommendations by Account ID with the <code>LINKED_ACCOUNT</code> dimension. To filter your recommendations by Account ID, specify <code>Key</code> as <code>LINKED_ACCOUNT</code> and <code>Value</code> as the comma-separated Acount ID(s) that you want to see Savings Plans purchase recommendations for.</p>
    /// <p>For GetSavingsPlansPurchaseRecommendation, the <code>Filter</code> doesn't include <code>CostCategories</code> or <code>Tags</code>. It only includes <code>Dimensions</code>. With <code>Dimensions</code>, <code>Key</code> must be <code>LINKED_ACCOUNT</code> and <code>Value</code> can be a single Account ID or multiple comma-separated Account IDs that you want to see Savings Plans Purchase Recommendations for. <code>AND</code> and <code>OR</code> operators are not supported.</p>
    pub filter: ::std::option::Option<crate::types::Expression>,
}
impl GetSavingsPlansPurchaseRecommendationInput {
    /// <p>The Savings Plans recommendation type that's requested.</p>
    pub fn savings_plans_type(&self) -> ::std::option::Option<&crate::types::SupportedSavingsPlansType> {
        self.savings_plans_type.as_ref()
    }
    /// <p>The savings plan recommendation term that's used to generate these recommendations.</p>
    pub fn term_in_years(&self) -> ::std::option::Option<&crate::types::TermInYears> {
        self.term_in_years.as_ref()
    }
    /// <p>The payment option that's used to generate these recommendations.</p>
    pub fn payment_option(&self) -> ::std::option::Option<&crate::types::PaymentOption> {
        self.payment_option.as_ref()
    }
    /// <p>The account scope that you want your recommendations for. Amazon Web Services calculates recommendations including the management account and member accounts if the value is set to <code>PAYER</code>. If the value is <code>LINKED</code>, recommendations are calculated for individual member accounts only.</p>
    pub fn account_scope(&self) -> ::std::option::Option<&crate::types::AccountScope> {
        self.account_scope.as_ref()
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
    /// <p>The number of recommendations that you want returned in a single response object.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
    /// <p>The lookback period that's used to generate the recommendation.</p>
    pub fn lookback_period_in_days(&self) -> ::std::option::Option<&crate::types::LookbackPeriodInDays> {
        self.lookback_period_in_days.as_ref()
    }
    /// <p>You can filter your recommendations by Account ID with the <code>LINKED_ACCOUNT</code> dimension. To filter your recommendations by Account ID, specify <code>Key</code> as <code>LINKED_ACCOUNT</code> and <code>Value</code> as the comma-separated Acount ID(s) that you want to see Savings Plans purchase recommendations for.</p>
    /// <p>For GetSavingsPlansPurchaseRecommendation, the <code>Filter</code> doesn't include <code>CostCategories</code> or <code>Tags</code>. It only includes <code>Dimensions</code>. With <code>Dimensions</code>, <code>Key</code> must be <code>LINKED_ACCOUNT</code> and <code>Value</code> can be a single Account ID or multiple comma-separated Account IDs that you want to see Savings Plans Purchase Recommendations for. <code>AND</code> and <code>OR</code> operators are not supported.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::Expression> {
        self.filter.as_ref()
    }
}
impl GetSavingsPlansPurchaseRecommendationInput {
    /// Creates a new builder-style object to manufacture [`GetSavingsPlansPurchaseRecommendationInput`](crate::operation::get_savings_plans_purchase_recommendation::GetSavingsPlansPurchaseRecommendationInput).
    pub fn builder() -> crate::operation::get_savings_plans_purchase_recommendation::builders::GetSavingsPlansPurchaseRecommendationInputBuilder {
        crate::operation::get_savings_plans_purchase_recommendation::builders::GetSavingsPlansPurchaseRecommendationInputBuilder::default()
    }
}

/// A builder for [`GetSavingsPlansPurchaseRecommendationInput`](crate::operation::get_savings_plans_purchase_recommendation::GetSavingsPlansPurchaseRecommendationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSavingsPlansPurchaseRecommendationInputBuilder {
    pub(crate) savings_plans_type: ::std::option::Option<crate::types::SupportedSavingsPlansType>,
    pub(crate) term_in_years: ::std::option::Option<crate::types::TermInYears>,
    pub(crate) payment_option: ::std::option::Option<crate::types::PaymentOption>,
    pub(crate) account_scope: ::std::option::Option<crate::types::AccountScope>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    pub(crate) page_size: ::std::option::Option<i32>,
    pub(crate) lookback_period_in_days: ::std::option::Option<crate::types::LookbackPeriodInDays>,
    pub(crate) filter: ::std::option::Option<crate::types::Expression>,
}
impl GetSavingsPlansPurchaseRecommendationInputBuilder {
    /// <p>The Savings Plans recommendation type that's requested.</p>
    /// This field is required.
    pub fn savings_plans_type(mut self, input: crate::types::SupportedSavingsPlansType) -> Self {
        self.savings_plans_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Savings Plans recommendation type that's requested.</p>
    pub fn set_savings_plans_type(mut self, input: ::std::option::Option<crate::types::SupportedSavingsPlansType>) -> Self {
        self.savings_plans_type = input;
        self
    }
    /// <p>The Savings Plans recommendation type that's requested.</p>
    pub fn get_savings_plans_type(&self) -> &::std::option::Option<crate::types::SupportedSavingsPlansType> {
        &self.savings_plans_type
    }
    /// <p>The savings plan recommendation term that's used to generate these recommendations.</p>
    /// This field is required.
    pub fn term_in_years(mut self, input: crate::types::TermInYears) -> Self {
        self.term_in_years = ::std::option::Option::Some(input);
        self
    }
    /// <p>The savings plan recommendation term that's used to generate these recommendations.</p>
    pub fn set_term_in_years(mut self, input: ::std::option::Option<crate::types::TermInYears>) -> Self {
        self.term_in_years = input;
        self
    }
    /// <p>The savings plan recommendation term that's used to generate these recommendations.</p>
    pub fn get_term_in_years(&self) -> &::std::option::Option<crate::types::TermInYears> {
        &self.term_in_years
    }
    /// <p>The payment option that's used to generate these recommendations.</p>
    /// This field is required.
    pub fn payment_option(mut self, input: crate::types::PaymentOption) -> Self {
        self.payment_option = ::std::option::Option::Some(input);
        self
    }
    /// <p>The payment option that's used to generate these recommendations.</p>
    pub fn set_payment_option(mut self, input: ::std::option::Option<crate::types::PaymentOption>) -> Self {
        self.payment_option = input;
        self
    }
    /// <p>The payment option that's used to generate these recommendations.</p>
    pub fn get_payment_option(&self) -> &::std::option::Option<crate::types::PaymentOption> {
        &self.payment_option
    }
    /// <p>The account scope that you want your recommendations for. Amazon Web Services calculates recommendations including the management account and member accounts if the value is set to <code>PAYER</code>. If the value is <code>LINKED</code>, recommendations are calculated for individual member accounts only.</p>
    pub fn account_scope(mut self, input: crate::types::AccountScope) -> Self {
        self.account_scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>The account scope that you want your recommendations for. Amazon Web Services calculates recommendations including the management account and member accounts if the value is set to <code>PAYER</code>. If the value is <code>LINKED</code>, recommendations are calculated for individual member accounts only.</p>
    pub fn set_account_scope(mut self, input: ::std::option::Option<crate::types::AccountScope>) -> Self {
        self.account_scope = input;
        self
    }
    /// <p>The account scope that you want your recommendations for. Amazon Web Services calculates recommendations including the management account and member accounts if the value is set to <code>PAYER</code>. If the value is <code>LINKED</code>, recommendations are calculated for individual member accounts only.</p>
    pub fn get_account_scope(&self) -> &::std::option::Option<crate::types::AccountScope> {
        &self.account_scope
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    /// <p>The number of recommendations that you want returned in a single response object.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of recommendations that you want returned in a single response object.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>The number of recommendations that you want returned in a single response object.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// <p>The lookback period that's used to generate the recommendation.</p>
    /// This field is required.
    pub fn lookback_period_in_days(mut self, input: crate::types::LookbackPeriodInDays) -> Self {
        self.lookback_period_in_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lookback period that's used to generate the recommendation.</p>
    pub fn set_lookback_period_in_days(mut self, input: ::std::option::Option<crate::types::LookbackPeriodInDays>) -> Self {
        self.lookback_period_in_days = input;
        self
    }
    /// <p>The lookback period that's used to generate the recommendation.</p>
    pub fn get_lookback_period_in_days(&self) -> &::std::option::Option<crate::types::LookbackPeriodInDays> {
        &self.lookback_period_in_days
    }
    /// <p>You can filter your recommendations by Account ID with the <code>LINKED_ACCOUNT</code> dimension. To filter your recommendations by Account ID, specify <code>Key</code> as <code>LINKED_ACCOUNT</code> and <code>Value</code> as the comma-separated Acount ID(s) that you want to see Savings Plans purchase recommendations for.</p>
    /// <p>For GetSavingsPlansPurchaseRecommendation, the <code>Filter</code> doesn't include <code>CostCategories</code> or <code>Tags</code>. It only includes <code>Dimensions</code>. With <code>Dimensions</code>, <code>Key</code> must be <code>LINKED_ACCOUNT</code> and <code>Value</code> can be a single Account ID or multiple comma-separated Account IDs that you want to see Savings Plans Purchase Recommendations for. <code>AND</code> and <code>OR</code> operators are not supported.</p>
    pub fn filter(mut self, input: crate::types::Expression) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>You can filter your recommendations by Account ID with the <code>LINKED_ACCOUNT</code> dimension. To filter your recommendations by Account ID, specify <code>Key</code> as <code>LINKED_ACCOUNT</code> and <code>Value</code> as the comma-separated Acount ID(s) that you want to see Savings Plans purchase recommendations for.</p>
    /// <p>For GetSavingsPlansPurchaseRecommendation, the <code>Filter</code> doesn't include <code>CostCategories</code> or <code>Tags</code>. It only includes <code>Dimensions</code>. With <code>Dimensions</code>, <code>Key</code> must be <code>LINKED_ACCOUNT</code> and <code>Value</code> can be a single Account ID or multiple comma-separated Account IDs that you want to see Savings Plans Purchase Recommendations for. <code>AND</code> and <code>OR</code> operators are not supported.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::Expression>) -> Self {
        self.filter = input;
        self
    }
    /// <p>You can filter your recommendations by Account ID with the <code>LINKED_ACCOUNT</code> dimension. To filter your recommendations by Account ID, specify <code>Key</code> as <code>LINKED_ACCOUNT</code> and <code>Value</code> as the comma-separated Acount ID(s) that you want to see Savings Plans purchase recommendations for.</p>
    /// <p>For GetSavingsPlansPurchaseRecommendation, the <code>Filter</code> doesn't include <code>CostCategories</code> or <code>Tags</code>. It only includes <code>Dimensions</code>. With <code>Dimensions</code>, <code>Key</code> must be <code>LINKED_ACCOUNT</code> and <code>Value</code> can be a single Account ID or multiple comma-separated Account IDs that you want to see Savings Plans Purchase Recommendations for. <code>AND</code> and <code>OR</code> operators are not supported.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::Expression> {
        &self.filter
    }
    /// Consumes the builder and constructs a [`GetSavingsPlansPurchaseRecommendationInput`](crate::operation::get_savings_plans_purchase_recommendation::GetSavingsPlansPurchaseRecommendationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_savings_plans_purchase_recommendation::GetSavingsPlansPurchaseRecommendationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_savings_plans_purchase_recommendation::GetSavingsPlansPurchaseRecommendationInput {
                savings_plans_type: self.savings_plans_type,
                term_in_years: self.term_in_years,
                payment_option: self.payment_option,
                account_scope: self.account_scope,
                next_page_token: self.next_page_token,
                page_size: self.page_size,
                lookback_period_in_days: self.lookback_period_in_days,
                filter: self.filter,
            },
        )
    }
}
