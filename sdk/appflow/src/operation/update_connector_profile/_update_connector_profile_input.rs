// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateConnectorProfileInput {
    /// <p>The name of the connector profile and is unique for each <code>ConnectorProfile</code> in the Amazon Web Services account.</p>
    pub connector_profile_name: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the connection mode and if it is public or private.</p>
    pub connection_mode: ::std::option::Option<crate::types::ConnectionMode>,
    /// <p>Defines the connector-specific profile configuration and credentials.</p>
    pub connector_profile_config: ::std::option::Option<crate::types::ConnectorProfileConfig>,
    /// <p>The <code>clientToken</code> parameter is an idempotency token. It ensures that your <code>UpdateConnectorProfile</code> request completes only once. You choose the value to pass. For example, if you don't receive a response from your request, you can safely retry the request with the same <code>clientToken</code> parameter value.</p>
    /// <p>If you omit a <code>clientToken</code> value, the Amazon Web Services SDK that you are using inserts a value for you. This way, the SDK can safely retry requests multiple times after a network error. You must provide your own value for other use cases.</p>
    /// <p>If you specify input parameters that differ from your first request, an error occurs. If you use a different value for <code>clientToken</code>, Amazon AppFlow considers it a new call to <code>UpdateConnectorProfile</code>. The token is active for 8 hours.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateConnectorProfileInput {
    /// <p>The name of the connector profile and is unique for each <code>ConnectorProfile</code> in the Amazon Web Services account.</p>
    pub fn connector_profile_name(&self) -> ::std::option::Option<&str> {
        self.connector_profile_name.as_deref()
    }
    /// <p>Indicates the connection mode and if it is public or private.</p>
    pub fn connection_mode(&self) -> ::std::option::Option<&crate::types::ConnectionMode> {
        self.connection_mode.as_ref()
    }
    /// <p>Defines the connector-specific profile configuration and credentials.</p>
    pub fn connector_profile_config(&self) -> ::std::option::Option<&crate::types::ConnectorProfileConfig> {
        self.connector_profile_config.as_ref()
    }
    /// <p>The <code>clientToken</code> parameter is an idempotency token. It ensures that your <code>UpdateConnectorProfile</code> request completes only once. You choose the value to pass. For example, if you don't receive a response from your request, you can safely retry the request with the same <code>clientToken</code> parameter value.</p>
    /// <p>If you omit a <code>clientToken</code> value, the Amazon Web Services SDK that you are using inserts a value for you. This way, the SDK can safely retry requests multiple times after a network error. You must provide your own value for other use cases.</p>
    /// <p>If you specify input parameters that differ from your first request, an error occurs. If you use a different value for <code>clientToken</code>, Amazon AppFlow considers it a new call to <code>UpdateConnectorProfile</code>. The token is active for 8 hours.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl UpdateConnectorProfileInput {
    /// Creates a new builder-style object to manufacture [`UpdateConnectorProfileInput`](crate::operation::update_connector_profile::UpdateConnectorProfileInput).
    pub fn builder() -> crate::operation::update_connector_profile::builders::UpdateConnectorProfileInputBuilder {
        crate::operation::update_connector_profile::builders::UpdateConnectorProfileInputBuilder::default()
    }
}

/// A builder for [`UpdateConnectorProfileInput`](crate::operation::update_connector_profile::UpdateConnectorProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateConnectorProfileInputBuilder {
    pub(crate) connector_profile_name: ::std::option::Option<::std::string::String>,
    pub(crate) connection_mode: ::std::option::Option<crate::types::ConnectionMode>,
    pub(crate) connector_profile_config: ::std::option::Option<crate::types::ConnectorProfileConfig>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateConnectorProfileInputBuilder {
    /// <p>The name of the connector profile and is unique for each <code>ConnectorProfile</code> in the Amazon Web Services account.</p>
    /// This field is required.
    pub fn connector_profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the connector profile and is unique for each <code>ConnectorProfile</code> in the Amazon Web Services account.</p>
    pub fn set_connector_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_profile_name = input;
        self
    }
    /// <p>The name of the connector profile and is unique for each <code>ConnectorProfile</code> in the Amazon Web Services account.</p>
    pub fn get_connector_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_profile_name
    }
    /// <p>Indicates the connection mode and if it is public or private.</p>
    /// This field is required.
    pub fn connection_mode(mut self, input: crate::types::ConnectionMode) -> Self {
        self.connection_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the connection mode and if it is public or private.</p>
    pub fn set_connection_mode(mut self, input: ::std::option::Option<crate::types::ConnectionMode>) -> Self {
        self.connection_mode = input;
        self
    }
    /// <p>Indicates the connection mode and if it is public or private.</p>
    pub fn get_connection_mode(&self) -> &::std::option::Option<crate::types::ConnectionMode> {
        &self.connection_mode
    }
    /// <p>Defines the connector-specific profile configuration and credentials.</p>
    /// This field is required.
    pub fn connector_profile_config(mut self, input: crate::types::ConnectorProfileConfig) -> Self {
        self.connector_profile_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the connector-specific profile configuration and credentials.</p>
    pub fn set_connector_profile_config(mut self, input: ::std::option::Option<crate::types::ConnectorProfileConfig>) -> Self {
        self.connector_profile_config = input;
        self
    }
    /// <p>Defines the connector-specific profile configuration and credentials.</p>
    pub fn get_connector_profile_config(&self) -> &::std::option::Option<crate::types::ConnectorProfileConfig> {
        &self.connector_profile_config
    }
    /// <p>The <code>clientToken</code> parameter is an idempotency token. It ensures that your <code>UpdateConnectorProfile</code> request completes only once. You choose the value to pass. For example, if you don't receive a response from your request, you can safely retry the request with the same <code>clientToken</code> parameter value.</p>
    /// <p>If you omit a <code>clientToken</code> value, the Amazon Web Services SDK that you are using inserts a value for you. This way, the SDK can safely retry requests multiple times after a network error. You must provide your own value for other use cases.</p>
    /// <p>If you specify input parameters that differ from your first request, an error occurs. If you use a different value for <code>clientToken</code>, Amazon AppFlow considers it a new call to <code>UpdateConnectorProfile</code>. The token is active for 8 hours.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>clientToken</code> parameter is an idempotency token. It ensures that your <code>UpdateConnectorProfile</code> request completes only once. You choose the value to pass. For example, if you don't receive a response from your request, you can safely retry the request with the same <code>clientToken</code> parameter value.</p>
    /// <p>If you omit a <code>clientToken</code> value, the Amazon Web Services SDK that you are using inserts a value for you. This way, the SDK can safely retry requests multiple times after a network error. You must provide your own value for other use cases.</p>
    /// <p>If you specify input parameters that differ from your first request, an error occurs. If you use a different value for <code>clientToken</code>, Amazon AppFlow considers it a new call to <code>UpdateConnectorProfile</code>. The token is active for 8 hours.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The <code>clientToken</code> parameter is an idempotency token. It ensures that your <code>UpdateConnectorProfile</code> request completes only once. You choose the value to pass. For example, if you don't receive a response from your request, you can safely retry the request with the same <code>clientToken</code> parameter value.</p>
    /// <p>If you omit a <code>clientToken</code> value, the Amazon Web Services SDK that you are using inserts a value for you. This way, the SDK can safely retry requests multiple times after a network error. You must provide your own value for other use cases.</p>
    /// <p>If you specify input parameters that differ from your first request, an error occurs. If you use a different value for <code>clientToken</code>, Amazon AppFlow considers it a new call to <code>UpdateConnectorProfile</code>. The token is active for 8 hours.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`UpdateConnectorProfileInput`](crate::operation::update_connector_profile::UpdateConnectorProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_connector_profile::UpdateConnectorProfileInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_connector_profile::UpdateConnectorProfileInput {
            connector_profile_name: self.connector_profile_name,
            connection_mode: self.connection_mode,
            connector_profile_config: self.connector_profile_config,
            client_token: self.client_token,
        })
    }
}
