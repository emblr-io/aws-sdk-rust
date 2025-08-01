// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response to a successful <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedRolePolicies.html">ListAttachedRolePolicies</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAttachedRolePoliciesOutput {
    /// <p>A list of the attached policies.</p>
    pub attached_policies: ::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>>,
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub is_truncated: bool,
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAttachedRolePoliciesOutput {
    /// <p>A list of the attached policies.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attached_policies.is_none()`.
    pub fn attached_policies(&self) -> &[crate::types::AttachedPolicy] {
        self.attached_policies.as_deref().unwrap_or_default()
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
impl ::aws_types::request_id::RequestId for ListAttachedRolePoliciesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAttachedRolePoliciesOutput {
    /// Creates a new builder-style object to manufacture [`ListAttachedRolePoliciesOutput`](crate::operation::list_attached_role_policies::ListAttachedRolePoliciesOutput).
    pub fn builder() -> crate::operation::list_attached_role_policies::builders::ListAttachedRolePoliciesOutputBuilder {
        crate::operation::list_attached_role_policies::builders::ListAttachedRolePoliciesOutputBuilder::default()
    }
}

/// A builder for [`ListAttachedRolePoliciesOutput`](crate::operation::list_attached_role_policies::ListAttachedRolePoliciesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAttachedRolePoliciesOutputBuilder {
    pub(crate) attached_policies: ::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>>,
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAttachedRolePoliciesOutputBuilder {
    /// Appends an item to `attached_policies`.
    ///
    /// To override the contents of this collection use [`set_attached_policies`](Self::set_attached_policies).
    ///
    /// <p>A list of the attached policies.</p>
    pub fn attached_policies(mut self, input: crate::types::AttachedPolicy) -> Self {
        let mut v = self.attached_policies.unwrap_or_default();
        v.push(input);
        self.attached_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the attached policies.</p>
    pub fn set_attached_policies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>>) -> Self {
        self.attached_policies = input;
        self
    }
    /// <p>A list of the attached policies.</p>
    pub fn get_attached_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>> {
        &self.attached_policies
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
    /// Consumes the builder and constructs a [`ListAttachedRolePoliciesOutput`](crate::operation::list_attached_role_policies::ListAttachedRolePoliciesOutput).
    pub fn build(self) -> crate::operation::list_attached_role_policies::ListAttachedRolePoliciesOutput {
        crate::operation::list_attached_role_policies::ListAttachedRolePoliciesOutput {
            attached_policies: self.attached_policies,
            is_truncated: self.is_truncated.unwrap_or_default(),
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
