// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSavingsPlansPurchaseRecommendationGenerationOutput {
    /// <p>The list of historical recommendation generations.</p>
    pub generation_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::GenerationSummary>>,
    /// <p>The token to retrieve the next set of results.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSavingsPlansPurchaseRecommendationGenerationOutput {
    /// <p>The list of historical recommendation generations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.generation_summary_list.is_none()`.
    pub fn generation_summary_list(&self) -> &[crate::types::GenerationSummary] {
        self.generation_summary_list.as_deref().unwrap_or_default()
    }
    /// <p>The token to retrieve the next set of results.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListSavingsPlansPurchaseRecommendationGenerationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSavingsPlansPurchaseRecommendationGenerationOutput {
    /// Creates a new builder-style object to manufacture [`ListSavingsPlansPurchaseRecommendationGenerationOutput`](crate::operation::list_savings_plans_purchase_recommendation_generation::ListSavingsPlansPurchaseRecommendationGenerationOutput).
    pub fn builder() -> crate::operation::list_savings_plans_purchase_recommendation_generation::builders::ListSavingsPlansPurchaseRecommendationGenerationOutputBuilder{
        crate::operation::list_savings_plans_purchase_recommendation_generation::builders::ListSavingsPlansPurchaseRecommendationGenerationOutputBuilder::default()
    }
}

/// A builder for [`ListSavingsPlansPurchaseRecommendationGenerationOutput`](crate::operation::list_savings_plans_purchase_recommendation_generation::ListSavingsPlansPurchaseRecommendationGenerationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSavingsPlansPurchaseRecommendationGenerationOutputBuilder {
    pub(crate) generation_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::GenerationSummary>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSavingsPlansPurchaseRecommendationGenerationOutputBuilder {
    /// Appends an item to `generation_summary_list`.
    ///
    /// To override the contents of this collection use [`set_generation_summary_list`](Self::set_generation_summary_list).
    ///
    /// <p>The list of historical recommendation generations.</p>
    pub fn generation_summary_list(mut self, input: crate::types::GenerationSummary) -> Self {
        let mut v = self.generation_summary_list.unwrap_or_default();
        v.push(input);
        self.generation_summary_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of historical recommendation generations.</p>
    pub fn set_generation_summary_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GenerationSummary>>) -> Self {
        self.generation_summary_list = input;
        self
    }
    /// <p>The list of historical recommendation generations.</p>
    pub fn get_generation_summary_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GenerationSummary>> {
        &self.generation_summary_list
    }
    /// <p>The token to retrieve the next set of results.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to retrieve the next set of results.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to retrieve the next set of results.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSavingsPlansPurchaseRecommendationGenerationOutput`](crate::operation::list_savings_plans_purchase_recommendation_generation::ListSavingsPlansPurchaseRecommendationGenerationOutput).
    pub fn build(
        self,
    ) -> crate::operation::list_savings_plans_purchase_recommendation_generation::ListSavingsPlansPurchaseRecommendationGenerationOutput {
        crate::operation::list_savings_plans_purchase_recommendation_generation::ListSavingsPlansPurchaseRecommendationGenerationOutput {
            generation_summary_list: self.generation_summary_list,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
