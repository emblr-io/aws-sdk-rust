// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAccountConfigurationInput {
    /// <p>Specifies expiration events associated with an account.</p>
    pub expiry_events: ::std::option::Option<crate::types::ExpiryEventsConfiguration>,
    /// <p>Customer-chosen string used to distinguish between calls to <code>PutAccountConfiguration</code>. Idempotency tokens time out after one hour. If you call <code>PutAccountConfiguration</code> multiple times with the same unexpired idempotency token, ACM treats it as the same request and returns the original result. If you change the idempotency token for each call, ACM treats each call as a new request.</p>
    pub idempotency_token: ::std::option::Option<::std::string::String>,
}
impl PutAccountConfigurationInput {
    /// <p>Specifies expiration events associated with an account.</p>
    pub fn expiry_events(&self) -> ::std::option::Option<&crate::types::ExpiryEventsConfiguration> {
        self.expiry_events.as_ref()
    }
    /// <p>Customer-chosen string used to distinguish between calls to <code>PutAccountConfiguration</code>. Idempotency tokens time out after one hour. If you call <code>PutAccountConfiguration</code> multiple times with the same unexpired idempotency token, ACM treats it as the same request and returns the original result. If you change the idempotency token for each call, ACM treats each call as a new request.</p>
    pub fn idempotency_token(&self) -> ::std::option::Option<&str> {
        self.idempotency_token.as_deref()
    }
}
impl PutAccountConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutAccountConfigurationInput`](crate::operation::put_account_configuration::PutAccountConfigurationInput).
    pub fn builder() -> crate::operation::put_account_configuration::builders::PutAccountConfigurationInputBuilder {
        crate::operation::put_account_configuration::builders::PutAccountConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutAccountConfigurationInput`](crate::operation::put_account_configuration::PutAccountConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAccountConfigurationInputBuilder {
    pub(crate) expiry_events: ::std::option::Option<crate::types::ExpiryEventsConfiguration>,
    pub(crate) idempotency_token: ::std::option::Option<::std::string::String>,
}
impl PutAccountConfigurationInputBuilder {
    /// <p>Specifies expiration events associated with an account.</p>
    pub fn expiry_events(mut self, input: crate::types::ExpiryEventsConfiguration) -> Self {
        self.expiry_events = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies expiration events associated with an account.</p>
    pub fn set_expiry_events(mut self, input: ::std::option::Option<crate::types::ExpiryEventsConfiguration>) -> Self {
        self.expiry_events = input;
        self
    }
    /// <p>Specifies expiration events associated with an account.</p>
    pub fn get_expiry_events(&self) -> &::std::option::Option<crate::types::ExpiryEventsConfiguration> {
        &self.expiry_events
    }
    /// <p>Customer-chosen string used to distinguish between calls to <code>PutAccountConfiguration</code>. Idempotency tokens time out after one hour. If you call <code>PutAccountConfiguration</code> multiple times with the same unexpired idempotency token, ACM treats it as the same request and returns the original result. If you change the idempotency token for each call, ACM treats each call as a new request.</p>
    /// This field is required.
    pub fn idempotency_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.idempotency_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Customer-chosen string used to distinguish between calls to <code>PutAccountConfiguration</code>. Idempotency tokens time out after one hour. If you call <code>PutAccountConfiguration</code> multiple times with the same unexpired idempotency token, ACM treats it as the same request and returns the original result. If you change the idempotency token for each call, ACM treats each call as a new request.</p>
    pub fn set_idempotency_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.idempotency_token = input;
        self
    }
    /// <p>Customer-chosen string used to distinguish between calls to <code>PutAccountConfiguration</code>. Idempotency tokens time out after one hour. If you call <code>PutAccountConfiguration</code> multiple times with the same unexpired idempotency token, ACM treats it as the same request and returns the original result. If you change the idempotency token for each call, ACM treats each call as a new request.</p>
    pub fn get_idempotency_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.idempotency_token
    }
    /// Consumes the builder and constructs a [`PutAccountConfigurationInput`](crate::operation::put_account_configuration::PutAccountConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_account_configuration::PutAccountConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_account_configuration::PutAccountConfigurationInput {
            expiry_events: self.expiry_events,
            idempotency_token: self.idempotency_token,
        })
    }
}
