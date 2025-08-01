// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetComplianceDetailsByConfigRuleOutput {
    /// <p>Indicates whether the Amazon Web Services resource complies with the specified Config rule.</p>
    pub evaluation_results: ::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>>,
    /// <p>The string that you use in a subsequent request to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetComplianceDetailsByConfigRuleOutput {
    /// <p>Indicates whether the Amazon Web Services resource complies with the specified Config rule.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.evaluation_results.is_none()`.
    pub fn evaluation_results(&self) -> &[crate::types::EvaluationResult] {
        self.evaluation_results.as_deref().unwrap_or_default()
    }
    /// <p>The string that you use in a subsequent request to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetComplianceDetailsByConfigRuleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetComplianceDetailsByConfigRuleOutput {
    /// Creates a new builder-style object to manufacture [`GetComplianceDetailsByConfigRuleOutput`](crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleOutput).
    pub fn builder() -> crate::operation::get_compliance_details_by_config_rule::builders::GetComplianceDetailsByConfigRuleOutputBuilder {
        crate::operation::get_compliance_details_by_config_rule::builders::GetComplianceDetailsByConfigRuleOutputBuilder::default()
    }
}

/// A builder for [`GetComplianceDetailsByConfigRuleOutput`](crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetComplianceDetailsByConfigRuleOutputBuilder {
    pub(crate) evaluation_results: ::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetComplianceDetailsByConfigRuleOutputBuilder {
    /// Appends an item to `evaluation_results`.
    ///
    /// To override the contents of this collection use [`set_evaluation_results`](Self::set_evaluation_results).
    ///
    /// <p>Indicates whether the Amazon Web Services resource complies with the specified Config rule.</p>
    pub fn evaluation_results(mut self, input: crate::types::EvaluationResult) -> Self {
        let mut v = self.evaluation_results.unwrap_or_default();
        v.push(input);
        self.evaluation_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates whether the Amazon Web Services resource complies with the specified Config rule.</p>
    pub fn set_evaluation_results(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>>) -> Self {
        self.evaluation_results = input;
        self
    }
    /// <p>Indicates whether the Amazon Web Services resource complies with the specified Config rule.</p>
    pub fn get_evaluation_results(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>> {
        &self.evaluation_results
    }
    /// <p>The string that you use in a subsequent request to get the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string that you use in a subsequent request to get the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The string that you use in a subsequent request to get the next page of results in a paginated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetComplianceDetailsByConfigRuleOutput`](crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleOutput).
    pub fn build(self) -> crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleOutput {
        crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleOutput {
            evaluation_results: self.evaluation_results,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
