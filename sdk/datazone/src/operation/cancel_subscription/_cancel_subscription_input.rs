// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelSubscriptionInput {
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription request is being cancelled.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the subscription that is being cancelled.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl CancelSubscriptionInput {
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription request is being cancelled.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The unique identifier of the subscription that is being cancelled.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl CancelSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`CancelSubscriptionInput`](crate::operation::cancel_subscription::CancelSubscriptionInput).
    pub fn builder() -> crate::operation::cancel_subscription::builders::CancelSubscriptionInputBuilder {
        crate::operation::cancel_subscription::builders::CancelSubscriptionInputBuilder::default()
    }
}

/// A builder for [`CancelSubscriptionInput`](crate::operation::cancel_subscription::CancelSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelSubscriptionInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl CancelSubscriptionInputBuilder {
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription request is being cancelled.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription request is being cancelled.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The unique identifier of the Amazon DataZone domain where the subscription request is being cancelled.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The unique identifier of the subscription that is being cancelled.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the subscription that is being cancelled.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The unique identifier of the subscription that is being cancelled.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`CancelSubscriptionInput`](crate::operation::cancel_subscription::CancelSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_subscription::CancelSubscriptionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_subscription::CancelSubscriptionInput {
            domain_identifier: self.domain_identifier,
            identifier: self.identifier,
        })
    }
}
