// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RevokeSubscriptionInput {
    /// <p>The identifier of the Amazon DataZone domain where you want to revoke a subscription.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the revoked subscription.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether permissions are retained when the subscription is revoked.</p>
    pub retain_permissions: ::std::option::Option<bool>,
}
impl RevokeSubscriptionInput {
    /// <p>The identifier of the Amazon DataZone domain where you want to revoke a subscription.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The identifier of the revoked subscription.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>Specifies whether permissions are retained when the subscription is revoked.</p>
    pub fn retain_permissions(&self) -> ::std::option::Option<bool> {
        self.retain_permissions
    }
}
impl RevokeSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`RevokeSubscriptionInput`](crate::operation::revoke_subscription::RevokeSubscriptionInput).
    pub fn builder() -> crate::operation::revoke_subscription::builders::RevokeSubscriptionInputBuilder {
        crate::operation::revoke_subscription::builders::RevokeSubscriptionInputBuilder::default()
    }
}

/// A builder for [`RevokeSubscriptionInput`](crate::operation::revoke_subscription::RevokeSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RevokeSubscriptionInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) retain_permissions: ::std::option::Option<bool>,
}
impl RevokeSubscriptionInputBuilder {
    /// <p>The identifier of the Amazon DataZone domain where you want to revoke a subscription.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain where you want to revoke a subscription.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain where you want to revoke a subscription.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The identifier of the revoked subscription.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the revoked subscription.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the revoked subscription.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>Specifies whether permissions are retained when the subscription is revoked.</p>
    pub fn retain_permissions(mut self, input: bool) -> Self {
        self.retain_permissions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether permissions are retained when the subscription is revoked.</p>
    pub fn set_retain_permissions(mut self, input: ::std::option::Option<bool>) -> Self {
        self.retain_permissions = input;
        self
    }
    /// <p>Specifies whether permissions are retained when the subscription is revoked.</p>
    pub fn get_retain_permissions(&self) -> &::std::option::Option<bool> {
        &self.retain_permissions
    }
    /// Consumes the builder and constructs a [`RevokeSubscriptionInput`](crate::operation::revoke_subscription::RevokeSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::revoke_subscription::RevokeSubscriptionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::revoke_subscription::RevokeSubscriptionInput {
            domain_identifier: self.domain_identifier,
            identifier: self.identifier,
            retain_permissions: self.retain_permissions,
        })
    }
}
