// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSubscriptionRequestDetailsInput {
    /// <p>The identifier of the Amazon DataZone domain in which to get the subscription request details.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the subscription request the details of which to get.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl GetSubscriptionRequestDetailsInput {
    /// <p>The identifier of the Amazon DataZone domain in which to get the subscription request details.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The identifier of the subscription request the details of which to get.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl GetSubscriptionRequestDetailsInput {
    /// Creates a new builder-style object to manufacture [`GetSubscriptionRequestDetailsInput`](crate::operation::get_subscription_request_details::GetSubscriptionRequestDetailsInput).
    pub fn builder() -> crate::operation::get_subscription_request_details::builders::GetSubscriptionRequestDetailsInputBuilder {
        crate::operation::get_subscription_request_details::builders::GetSubscriptionRequestDetailsInputBuilder::default()
    }
}

/// A builder for [`GetSubscriptionRequestDetailsInput`](crate::operation::get_subscription_request_details::GetSubscriptionRequestDetailsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSubscriptionRequestDetailsInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl GetSubscriptionRequestDetailsInputBuilder {
    /// <p>The identifier of the Amazon DataZone domain in which to get the subscription request details.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which to get the subscription request details.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which to get the subscription request details.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The identifier of the subscription request the details of which to get.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the subscription request the details of which to get.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the subscription request the details of which to get.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`GetSubscriptionRequestDetailsInput`](crate::operation::get_subscription_request_details::GetSubscriptionRequestDetailsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_subscription_request_details::GetSubscriptionRequestDetailsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_subscription_request_details::GetSubscriptionRequestDetailsInput {
            domain_identifier: self.domain_identifier,
            identifier: self.identifier,
        })
    }
}
