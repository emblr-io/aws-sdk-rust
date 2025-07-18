// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEffectivePermissionsForPathOutput {
    /// <p>A list of the permissions for the specified table or database resource located at the path in Amazon S3.</p>
    pub permissions: ::std::option::Option<::std::vec::Vec<crate::types::PrincipalResourcePermissions>>,
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetEffectivePermissionsForPathOutput {
    /// <p>A list of the permissions for the specified table or database resource located at the path in Amazon S3.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.permissions.is_none()`.
    pub fn permissions(&self) -> &[crate::types::PrincipalResourcePermissions] {
        self.permissions.as_deref().unwrap_or_default()
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetEffectivePermissionsForPathOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEffectivePermissionsForPathOutput {
    /// Creates a new builder-style object to manufacture [`GetEffectivePermissionsForPathOutput`](crate::operation::get_effective_permissions_for_path::GetEffectivePermissionsForPathOutput).
    pub fn builder() -> crate::operation::get_effective_permissions_for_path::builders::GetEffectivePermissionsForPathOutputBuilder {
        crate::operation::get_effective_permissions_for_path::builders::GetEffectivePermissionsForPathOutputBuilder::default()
    }
}

/// A builder for [`GetEffectivePermissionsForPathOutput`](crate::operation::get_effective_permissions_for_path::GetEffectivePermissionsForPathOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEffectivePermissionsForPathOutputBuilder {
    pub(crate) permissions: ::std::option::Option<::std::vec::Vec<crate::types::PrincipalResourcePermissions>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetEffectivePermissionsForPathOutputBuilder {
    /// Appends an item to `permissions`.
    ///
    /// To override the contents of this collection use [`set_permissions`](Self::set_permissions).
    ///
    /// <p>A list of the permissions for the specified table or database resource located at the path in Amazon S3.</p>
    pub fn permissions(mut self, input: crate::types::PrincipalResourcePermissions) -> Self {
        let mut v = self.permissions.unwrap_or_default();
        v.push(input);
        self.permissions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the permissions for the specified table or database resource located at the path in Amazon S3.</p>
    pub fn set_permissions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PrincipalResourcePermissions>>) -> Self {
        self.permissions = input;
        self
    }
    /// <p>A list of the permissions for the specified table or database resource located at the path in Amazon S3.</p>
    pub fn get_permissions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PrincipalResourcePermissions>> {
        &self.permissions
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if this is not the first call to retrieve this list.</p>
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
    /// Consumes the builder and constructs a [`GetEffectivePermissionsForPathOutput`](crate::operation::get_effective_permissions_for_path::GetEffectivePermissionsForPathOutput).
    pub fn build(self) -> crate::operation::get_effective_permissions_for_path::GetEffectivePermissionsForPathOutput {
        crate::operation::get_effective_permissions_for_path::GetEffectivePermissionsForPathOutput {
            permissions: self.permissions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
