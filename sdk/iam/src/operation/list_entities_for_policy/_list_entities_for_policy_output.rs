// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the response to a successful <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListEntitiesForPolicy.html">ListEntitiesForPolicy</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEntitiesForPolicyOutput {
    /// <p>A list of IAM groups that the policy is attached to.</p>
    pub policy_groups: ::std::option::Option<::std::vec::Vec<crate::types::PolicyGroup>>,
    /// <p>A list of IAM users that the policy is attached to.</p>
    pub policy_users: ::std::option::Option<::std::vec::Vec<crate::types::PolicyUser>>,
    /// <p>A list of IAM roles that the policy is attached to.</p>
    pub policy_roles: ::std::option::Option<::std::vec::Vec<crate::types::PolicyRole>>,
    /// <p>A flag that indicates whether there are more items to return. If your results were truncated, you can make a subsequent pagination request using the <code>Marker</code> request parameter to retrieve more items. Note that IAM might return fewer than the <code>MaxItems</code> number of results even when there are more results available. We recommend that you check <code>IsTruncated</code> after every call to ensure that you receive all your results.</p>
    pub is_truncated: bool,
    /// <p>When <code>IsTruncated</code> is <code>true</code>, this element is present and contains the value to use for the <code>Marker</code> parameter in a subsequent pagination request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListEntitiesForPolicyOutput {
    /// <p>A list of IAM groups that the policy is attached to.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policy_groups.is_none()`.
    pub fn policy_groups(&self) -> &[crate::types::PolicyGroup] {
        self.policy_groups.as_deref().unwrap_or_default()
    }
    /// <p>A list of IAM users that the policy is attached to.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policy_users.is_none()`.
    pub fn policy_users(&self) -> &[crate::types::PolicyUser] {
        self.policy_users.as_deref().unwrap_or_default()
    }
    /// <p>A list of IAM roles that the policy is attached to.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.policy_roles.is_none()`.
    pub fn policy_roles(&self) -> &[crate::types::PolicyRole] {
        self.policy_roles.as_deref().unwrap_or_default()
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
impl ::aws_types::request_id::RequestId for ListEntitiesForPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListEntitiesForPolicyOutput {
    /// Creates a new builder-style object to manufacture [`ListEntitiesForPolicyOutput`](crate::operation::list_entities_for_policy::ListEntitiesForPolicyOutput).
    pub fn builder() -> crate::operation::list_entities_for_policy::builders::ListEntitiesForPolicyOutputBuilder {
        crate::operation::list_entities_for_policy::builders::ListEntitiesForPolicyOutputBuilder::default()
    }
}

/// A builder for [`ListEntitiesForPolicyOutput`](crate::operation::list_entities_for_policy::ListEntitiesForPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEntitiesForPolicyOutputBuilder {
    pub(crate) policy_groups: ::std::option::Option<::std::vec::Vec<crate::types::PolicyGroup>>,
    pub(crate) policy_users: ::std::option::Option<::std::vec::Vec<crate::types::PolicyUser>>,
    pub(crate) policy_roles: ::std::option::Option<::std::vec::Vec<crate::types::PolicyRole>>,
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListEntitiesForPolicyOutputBuilder {
    /// Appends an item to `policy_groups`.
    ///
    /// To override the contents of this collection use [`set_policy_groups`](Self::set_policy_groups).
    ///
    /// <p>A list of IAM groups that the policy is attached to.</p>
    pub fn policy_groups(mut self, input: crate::types::PolicyGroup) -> Self {
        let mut v = self.policy_groups.unwrap_or_default();
        v.push(input);
        self.policy_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of IAM groups that the policy is attached to.</p>
    pub fn set_policy_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PolicyGroup>>) -> Self {
        self.policy_groups = input;
        self
    }
    /// <p>A list of IAM groups that the policy is attached to.</p>
    pub fn get_policy_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PolicyGroup>> {
        &self.policy_groups
    }
    /// Appends an item to `policy_users`.
    ///
    /// To override the contents of this collection use [`set_policy_users`](Self::set_policy_users).
    ///
    /// <p>A list of IAM users that the policy is attached to.</p>
    pub fn policy_users(mut self, input: crate::types::PolicyUser) -> Self {
        let mut v = self.policy_users.unwrap_or_default();
        v.push(input);
        self.policy_users = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of IAM users that the policy is attached to.</p>
    pub fn set_policy_users(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PolicyUser>>) -> Self {
        self.policy_users = input;
        self
    }
    /// <p>A list of IAM users that the policy is attached to.</p>
    pub fn get_policy_users(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PolicyUser>> {
        &self.policy_users
    }
    /// Appends an item to `policy_roles`.
    ///
    /// To override the contents of this collection use [`set_policy_roles`](Self::set_policy_roles).
    ///
    /// <p>A list of IAM roles that the policy is attached to.</p>
    pub fn policy_roles(mut self, input: crate::types::PolicyRole) -> Self {
        let mut v = self.policy_roles.unwrap_or_default();
        v.push(input);
        self.policy_roles = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of IAM roles that the policy is attached to.</p>
    pub fn set_policy_roles(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PolicyRole>>) -> Self {
        self.policy_roles = input;
        self
    }
    /// <p>A list of IAM roles that the policy is attached to.</p>
    pub fn get_policy_roles(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PolicyRole>> {
        &self.policy_roles
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
    /// Consumes the builder and constructs a [`ListEntitiesForPolicyOutput`](crate::operation::list_entities_for_policy::ListEntitiesForPolicyOutput).
    pub fn build(self) -> crate::operation::list_entities_for_policy::ListEntitiesForPolicyOutput {
        crate::operation::list_entities_for_policy::ListEntitiesForPolicyOutput {
            policy_groups: self.policy_groups,
            policy_users: self.policy_users,
            policy_roles: self.policy_roles,
            is_truncated: self.is_truncated.unwrap_or_default(),
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
