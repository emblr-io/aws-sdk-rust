// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnableFederationInput {
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to enable Lake query federation.</p>
    pub event_data_store: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the federation role to use for the event data store. Amazon Web Services services like Lake Formation use this federation role to access data for the federated event data store. The federation role must exist in your account and provide the <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-federation.html#query-federation-permissions-role">required minimum permissions</a>.</p>
    pub federation_role_arn: ::std::option::Option<::std::string::String>,
}
impl EnableFederationInput {
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to enable Lake query federation.</p>
    pub fn event_data_store(&self) -> ::std::option::Option<&str> {
        self.event_data_store.as_deref()
    }
    /// <p>The ARN of the federation role to use for the event data store. Amazon Web Services services like Lake Formation use this federation role to access data for the federated event data store. The federation role must exist in your account and provide the <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-federation.html#query-federation-permissions-role">required minimum permissions</a>.</p>
    pub fn federation_role_arn(&self) -> ::std::option::Option<&str> {
        self.federation_role_arn.as_deref()
    }
}
impl EnableFederationInput {
    /// Creates a new builder-style object to manufacture [`EnableFederationInput`](crate::operation::enable_federation::EnableFederationInput).
    pub fn builder() -> crate::operation::enable_federation::builders::EnableFederationInputBuilder {
        crate::operation::enable_federation::builders::EnableFederationInputBuilder::default()
    }
}

/// A builder for [`EnableFederationInput`](crate::operation::enable_federation::EnableFederationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnableFederationInputBuilder {
    pub(crate) event_data_store: ::std::option::Option<::std::string::String>,
    pub(crate) federation_role_arn: ::std::option::Option<::std::string::String>,
}
impl EnableFederationInputBuilder {
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to enable Lake query federation.</p>
    /// This field is required.
    pub fn event_data_store(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to enable Lake query federation.</p>
    pub fn set_event_data_store(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store = input;
        self
    }
    /// <p>The ARN (or ID suffix of the ARN) of the event data store for which you want to enable Lake query federation.</p>
    pub fn get_event_data_store(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store
    }
    /// <p>The ARN of the federation role to use for the event data store. Amazon Web Services services like Lake Formation use this federation role to access data for the federated event data store. The federation role must exist in your account and provide the <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-federation.html#query-federation-permissions-role">required minimum permissions</a>.</p>
    /// This field is required.
    pub fn federation_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.federation_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the federation role to use for the event data store. Amazon Web Services services like Lake Formation use this federation role to access data for the federated event data store. The federation role must exist in your account and provide the <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-federation.html#query-federation-permissions-role">required minimum permissions</a>.</p>
    pub fn set_federation_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.federation_role_arn = input;
        self
    }
    /// <p>The ARN of the federation role to use for the event data store. Amazon Web Services services like Lake Formation use this federation role to access data for the federated event data store. The federation role must exist in your account and provide the <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/query-federation.html#query-federation-permissions-role">required minimum permissions</a>.</p>
    pub fn get_federation_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.federation_role_arn
    }
    /// Consumes the builder and constructs a [`EnableFederationInput`](crate::operation::enable_federation::EnableFederationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::enable_federation::EnableFederationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::enable_federation::EnableFederationInput {
            event_data_store: self.event_data_store,
            federation_role_arn: self.federation_role_arn,
        })
    }
}
