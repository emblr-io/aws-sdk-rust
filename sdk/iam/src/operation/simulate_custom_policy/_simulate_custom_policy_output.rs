// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response to a successful <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html">SimulatePrincipalPolicy</a> or <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html">SimulateCustomPolicy</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SimulateCustomPolicyOutput {
    /// <p>The results of the simulation.</p>
    pub evaluation_results: ::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>>,
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub is_truncated: bool,
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SimulateCustomPolicyOutput {
    /// <p>The results of the simulation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.evaluation_results.is_none()`.
    pub fn evaluation_results(&self) -> &[crate::types::EvaluationResult] {
        self.evaluation_results.as_deref().unwrap_or_default()
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SimulateCustomPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SimulateCustomPolicyOutput {
    /// Creates a new builder-style object to manufacture [`SimulateCustomPolicyOutput`](crate::operation::simulate_custom_policy::SimulateCustomPolicyOutput).
    pub fn builder() -> crate::operation::simulate_custom_policy::builders::SimulateCustomPolicyOutputBuilder {
        crate::operation::simulate_custom_policy::builders::SimulateCustomPolicyOutputBuilder::default()
    }
}

/// A builder for [`SimulateCustomPolicyOutput`](crate::operation::simulate_custom_policy::SimulateCustomPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SimulateCustomPolicyOutputBuilder {
    pub(crate) evaluation_results: ::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>>,
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SimulateCustomPolicyOutputBuilder {
    /// Appends an item to `evaluation_results`.
    ///
    /// To override the contents of this collection use [`set_evaluation_results`](Self::set_evaluation_results).
    ///
    /// <p>The results of the simulation.</p>
    pub fn evaluation_results(mut self, input: crate::types::EvaluationResult) -> Self {
        let mut v = self.evaluation_results.unwrap_or_default();
        v.push(input);
        self.evaluation_results = ::std::option::Option::Some(v);
        self
    }
    /// <p>The results of the simulation.</p>
    pub fn set_evaluation_results(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>>) -> Self {
        self.evaluation_results = input;
        self
    }
    /// <p>The results of the simulation.</p>
    pub fn get_evaluation_results(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EvaluationResult>> {
        &self.evaluation_results
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn is_truncated(mut self, input: bool) -> Self {
        self.is_truncated = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn set_is_truncated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_truncated = input;
        self
    }
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub fn get_is_truncated(&self) -> &::std::option::Option<bool> {
        &self.is_truncated
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SimulateCustomPolicyOutput`](crate::operation::simulate_custom_policy::SimulateCustomPolicyOutput).
    pub fn build(self) -> crate::operation::simulate_custom_policy::SimulateCustomPolicyOutput {
        crate::operation::simulate_custom_policy::SimulateCustomPolicyOutput {
            evaluation_results: self.evaluation_results,
            is_truncated: self.is_truncated.unwrap_or_default(),
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
