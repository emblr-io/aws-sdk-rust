// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSavingsPlanPurchaseRecommendationDetailsInput {
    /// <p>The ID that is associated with the Savings Plan recommendation.</p>
    pub recommendation_detail_id: ::std::option::Option<::std::string::String>,
}
impl GetSavingsPlanPurchaseRecommendationDetailsInput {
    /// <p>The ID that is associated with the Savings Plan recommendation.</p>
    pub fn recommendation_detail_id(&self) -> ::std::option::Option<&str> {
        self.recommendation_detail_id.as_deref()
    }
}
impl GetSavingsPlanPurchaseRecommendationDetailsInput {
    /// Creates a new builder-style object to manufacture [`GetSavingsPlanPurchaseRecommendationDetailsInput`](crate::operation::get_savings_plan_purchase_recommendation_details::GetSavingsPlanPurchaseRecommendationDetailsInput).
    pub fn builder(
    ) -> crate::operation::get_savings_plan_purchase_recommendation_details::builders::GetSavingsPlanPurchaseRecommendationDetailsInputBuilder {
        crate::operation::get_savings_plan_purchase_recommendation_details::builders::GetSavingsPlanPurchaseRecommendationDetailsInputBuilder::default(
        )
    }
}

/// A builder for [`GetSavingsPlanPurchaseRecommendationDetailsInput`](crate::operation::get_savings_plan_purchase_recommendation_details::GetSavingsPlanPurchaseRecommendationDetailsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSavingsPlanPurchaseRecommendationDetailsInputBuilder {
    pub(crate) recommendation_detail_id: ::std::option::Option<::std::string::String>,
}
impl GetSavingsPlanPurchaseRecommendationDetailsInputBuilder {
    /// <p>The ID that is associated with the Savings Plan recommendation.</p>
    /// This field is required.
    pub fn recommendation_detail_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_detail_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID that is associated with the Savings Plan recommendation.</p>
    pub fn set_recommendation_detail_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_detail_id = input;
        self
    }
    /// <p>The ID that is associated with the Savings Plan recommendation.</p>
    pub fn get_recommendation_detail_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_detail_id
    }
    /// Consumes the builder and constructs a [`GetSavingsPlanPurchaseRecommendationDetailsInput`](crate::operation::get_savings_plan_purchase_recommendation_details::GetSavingsPlanPurchaseRecommendationDetailsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_savings_plan_purchase_recommendation_details::GetSavingsPlanPurchaseRecommendationDetailsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_savings_plan_purchase_recommendation_details::GetSavingsPlanPurchaseRecommendationDetailsInput {
                recommendation_detail_id: self.recommendation_detail_id,
            },
        )
    }
}
