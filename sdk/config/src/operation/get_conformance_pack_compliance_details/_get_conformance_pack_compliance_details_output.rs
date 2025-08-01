// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConformancePackComplianceDetailsOutput {
    /// <p>Name of the conformance pack.</p>
    pub conformance_pack_name: ::std::string::String,
    /// <p>Returns a list of <code>ConformancePackEvaluationResult</code> objects.</p>
    pub conformance_pack_rule_evaluation_results: ::std::option::Option<::std::vec::Vec<crate::types::ConformancePackEvaluationResult>>,
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetConformancePackComplianceDetailsOutput {
    /// <p>Name of the conformance pack.</p>
    pub fn conformance_pack_name(&self) -> &str {
        use std::ops::Deref;
        self.conformance_pack_name.deref()
    }
    /// <p>Returns a list of <code>ConformancePackEvaluationResult</code> objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.conformance_pack_rule_evaluation_results.is_none()`.
    pub fn conformance_pack_rule_evaluation_results(&self) -> &[crate::types::ConformancePackEvaluationResult] {
        self.conformance_pack_rule_evaluation_results.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetConformancePackComplianceDetailsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetConformancePackComplianceDetailsOutput {
    /// Creates a new builder-style object to manufacture [`GetConformancePackComplianceDetailsOutput`](crate::operation::get_conformance_pack_compliance_details::GetConformancePackComplianceDetailsOutput).
    pub fn builder() -> crate::operation::get_conformance_pack_compliance_details::builders::GetConformancePackComplianceDetailsOutputBuilder {
        crate::operation::get_conformance_pack_compliance_details::builders::GetConformancePackComplianceDetailsOutputBuilder::default()
    }
}

/// A builder for [`GetConformancePackComplianceDetailsOutput`](crate::operation::get_conformance_pack_compliance_details::GetConformancePackComplianceDetailsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConformancePackComplianceDetailsOutputBuilder {
    pub(crate) conformance_pack_name: ::std::option::Option<::std::string::String>,
    pub(crate) conformance_pack_rule_evaluation_results: ::std::option::Option<::std::vec::Vec<crate::types::ConformancePackEvaluationResult>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetConformancePackComplianceDetailsOutputBuilder {
    /// <p>Name of the conformance pack.</p>
    /// This field is required.
    pub fn conformance_pack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conformance_pack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the conformance pack.</p>
    pub fn set_conformance_pack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conformance_pack_name = input;
        self
    }
    /// <p>Name of the conformance pack.</p>
    pub fn get_conformance_pack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.conformance_pack_name
    }
    /// Appends an item to `conformance_pack_rule_evaluation_results`.
    ///
    /// To override the contents of this collection use [`set_conformance_pack_rule_evaluation_results`](Self::set_conformance_pack_rule_evaluation_results).
    ///
    /// <p>Returns a list of <code>ConformancePackEvaluationResult</code> objects.</p>
    pub fn conformance_pack_rule_evaluation_results(mut self, input: crate::types::ConformancePackEvaluationResult) -> Self {
        let mut v = self.conformance_pack_rule_evaluation_results.unwrap_or_default();
        v.push(input);
        self.conformance_pack_rule_evaluation_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns a list of <code>ConformancePackEvaluationResult</code> objects.</p>
    pub fn set_conformance_pack_rule_evaluation_results(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::ConformancePackEvaluationResult>>,
    ) -> Self {
        self.conformance_pack_rule_evaluation_results = input;
        self
    }
    /// <p>Returns a list of <code>ConformancePackEvaluationResult</code> objects.</p>
    pub fn get_conformance_pack_rule_evaluation_results(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::ConformancePackEvaluationResult>> {
        &self.conformance_pack_rule_evaluation_results
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned in a previous request that you use to request the next page of results in a paginated response.</p>
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
    /// Consumes the builder and constructs a [`GetConformancePackComplianceDetailsOutput`](crate::operation::get_conformance_pack_compliance_details::GetConformancePackComplianceDetailsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`conformance_pack_name`](crate::operation::get_conformance_pack_compliance_details::builders::GetConformancePackComplianceDetailsOutputBuilder::conformance_pack_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_conformance_pack_compliance_details::GetConformancePackComplianceDetailsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_conformance_pack_compliance_details::GetConformancePackComplianceDetailsOutput {
                conformance_pack_name: self.conformance_pack_name.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "conformance_pack_name",
                        "conformance_pack_name was not specified but it is required when building GetConformancePackComplianceDetailsOutput",
                    )
                })?,
                conformance_pack_rule_evaluation_results: self.conformance_pack_rule_evaluation_results,
                next_token: self.next_token,
                _request_id: self._request_id,
            },
        )
    }
}
