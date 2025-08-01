// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProfilePermissionsOutput {
    /// <p>The identifier for the current revision of profile permissions.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    /// <p>Total size of the policy associated with the Signing Profile in bytes.</p>
    pub policy_size_bytes: i32,
    /// <p>List of permissions associated with the Signing Profile.</p>
    pub permissions: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>,
    /// <p>String for specifying the next set of paginated results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListProfilePermissionsOutput {
    /// <p>The identifier for the current revision of profile permissions.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
    /// <p>Total size of the policy associated with the Signing Profile in bytes.</p>
    pub fn policy_size_bytes(&self) -> i32 {
        self.policy_size_bytes
    }
    /// <p>List of permissions associated with the Signing Profile.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.permissions.is_none()`.
    pub fn permissions(&self) -> &[crate::types::Permission] {
        self.permissions.as_deref().unwrap_or_default()
    }
    /// <p>String for specifying the next set of paginated results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListProfilePermissionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListProfilePermissionsOutput {
    /// Creates a new builder-style object to manufacture [`ListProfilePermissionsOutput`](crate::operation::list_profile_permissions::ListProfilePermissionsOutput).
    pub fn builder() -> crate::operation::list_profile_permissions::builders::ListProfilePermissionsOutputBuilder {
        crate::operation::list_profile_permissions::builders::ListProfilePermissionsOutputBuilder::default()
    }
}

/// A builder for [`ListProfilePermissionsOutput`](crate::operation::list_profile_permissions::ListProfilePermissionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProfilePermissionsOutputBuilder {
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_size_bytes: ::std::option::Option<i32>,
    pub(crate) permissions: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListProfilePermissionsOutputBuilder {
    /// <p>The identifier for the current revision of profile permissions.</p>
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the current revision of profile permissions.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The identifier for the current revision of profile permissions.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// <p>Total size of the policy associated with the Signing Profile in bytes.</p>
    pub fn policy_size_bytes(mut self, input: i32) -> Self {
        self.policy_size_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Total size of the policy associated with the Signing Profile in bytes.</p>
    pub fn set_policy_size_bytes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.policy_size_bytes = input;
        self
    }
    /// <p>Total size of the policy associated with the Signing Profile in bytes.</p>
    pub fn get_policy_size_bytes(&self) -> &::std::option::Option<i32> {
        &self.policy_size_bytes
    }
    /// Appends an item to `permissions`.
    ///
    /// To override the contents of this collection use [`set_permissions`](Self::set_permissions).
    ///
    /// <p>List of permissions associated with the Signing Profile.</p>
    pub fn permissions(mut self, input: crate::types::Permission) -> Self {
        let mut v = self.permissions.unwrap_or_default();
        v.push(input);
        self.permissions = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of permissions associated with the Signing Profile.</p>
    pub fn set_permissions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Permission>>) -> Self {
        self.permissions = input;
        self
    }
    /// <p>List of permissions associated with the Signing Profile.</p>
    pub fn get_permissions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Permission>> {
        &self.permissions
    }
    /// <p>String for specifying the next set of paginated results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>String for specifying the next set of paginated results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>String for specifying the next set of paginated results.</p>
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
    /// Consumes the builder and constructs a [`ListProfilePermissionsOutput`](crate::operation::list_profile_permissions::ListProfilePermissionsOutput).
    pub fn build(self) -> crate::operation::list_profile_permissions::ListProfilePermissionsOutput {
        crate::operation::list_profile_permissions::ListProfilePermissionsOutput {
            revision_id: self.revision_id,
            policy_size_bytes: self.policy_size_bytes.unwrap_or_default(),
            permissions: self.permissions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
