// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAuthorizationTokenInput {
    /// <p>A list of Amazon Web Services account IDs that are associated with the registries for which to get AuthorizationData objects. If you do not specify a registry, the default registry is assumed.</p>
    #[deprecated(
        note = "This field is deprecated. The returned authorization token can be used to access any Amazon ECR registry that the IAM principal has access to, specifying a registry ID doesn't change the permissions scope of the authorization token."
    )]
    pub registry_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetAuthorizationTokenInput {
    /// <p>A list of Amazon Web Services account IDs that are associated with the registries for which to get AuthorizationData objects. If you do not specify a registry, the default registry is assumed.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.registry_ids.is_none()`.
    #[deprecated(
        note = "This field is deprecated. The returned authorization token can be used to access any Amazon ECR registry that the IAM principal has access to, specifying a registry ID doesn't change the permissions scope of the authorization token."
    )]
    pub fn registry_ids(&self) -> &[::std::string::String] {
        self.registry_ids.as_deref().unwrap_or_default()
    }
}
impl GetAuthorizationTokenInput {
    /// Creates a new builder-style object to manufacture [`GetAuthorizationTokenInput`](crate::operation::get_authorization_token::GetAuthorizationTokenInput).
    pub fn builder() -> crate::operation::get_authorization_token::builders::GetAuthorizationTokenInputBuilder {
        crate::operation::get_authorization_token::builders::GetAuthorizationTokenInputBuilder::default()
    }
}

/// A builder for [`GetAuthorizationTokenInput`](crate::operation::get_authorization_token::GetAuthorizationTokenInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAuthorizationTokenInputBuilder {
    pub(crate) registry_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GetAuthorizationTokenInputBuilder {
    /// Appends an item to `registry_ids`.
    ///
    /// To override the contents of this collection use [`set_registry_ids`](Self::set_registry_ids).
    ///
    /// <p>A list of Amazon Web Services account IDs that are associated with the registries for which to get AuthorizationData objects. If you do not specify a registry, the default registry is assumed.</p>
    #[deprecated(
        note = "This field is deprecated. The returned authorization token can be used to access any Amazon ECR registry that the IAM principal has access to, specifying a registry ID doesn't change the permissions scope of the authorization token."
    )]
    pub fn registry_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.registry_ids.unwrap_or_default();
        v.push(input.into());
        self.registry_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of Amazon Web Services account IDs that are associated with the registries for which to get AuthorizationData objects. If you do not specify a registry, the default registry is assumed.</p>
    #[deprecated(
        note = "This field is deprecated. The returned authorization token can be used to access any Amazon ECR registry that the IAM principal has access to, specifying a registry ID doesn't change the permissions scope of the authorization token."
    )]
    pub fn set_registry_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.registry_ids = input;
        self
    }
    /// <p>A list of Amazon Web Services account IDs that are associated with the registries for which to get AuthorizationData objects. If you do not specify a registry, the default registry is assumed.</p>
    #[deprecated(
        note = "This field is deprecated. The returned authorization token can be used to access any Amazon ECR registry that the IAM principal has access to, specifying a registry ID doesn't change the permissions scope of the authorization token."
    )]
    pub fn get_registry_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.registry_ids
    }
    /// Consumes the builder and constructs a [`GetAuthorizationTokenInput`](crate::operation::get_authorization_token::GetAuthorizationTokenInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_authorization_token::GetAuthorizationTokenInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_authorization_token::GetAuthorizationTokenInput {
            registry_ids: self.registry_ids,
        })
    }
}
