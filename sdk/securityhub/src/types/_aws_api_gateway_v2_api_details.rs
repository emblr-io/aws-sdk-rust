// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a version 2 API in Amazon API Gateway.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsApiGatewayV2ApiDetails {
    /// <p>The URI of the API.</p>
    /// <p>Uses the format <code> <i><api-id></api-id></i>.execute-api.<i><region></region></i>.amazonaws.com</code></p>
    /// <p>The stage name is typically appended to the URI to form a complete path to a deployed API stage.</p>
    pub api_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the API.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>An API key selection expression. Supported only for WebSocket APIs.</p>
    pub api_key_selection_expression: ::std::option::Option<::std::string::String>,
    /// <p>Indicates when the API was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub created_date: ::std::option::Option<::std::string::String>,
    /// <p>A description of the API.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The version identifier for the API.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The name of the API.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The API protocol for the API.</p>
    /// <p>Valid values: <code>WEBSOCKET</code> | <code>HTTP</code></p>
    pub protocol_type: ::std::option::Option<::std::string::String>,
    /// <p>The route selection expression for the API.</p>
    /// <p>For HTTP APIs, must be <code>${request.method} ${request.path}</code>. This is the default value for HTTP APIs.</p>
    /// <p>For WebSocket APIs, there is no default value.</p>
    pub route_selection_expression: ::std::option::Option<::std::string::String>,
    /// <p>A cross-origin resource sharing (CORS) configuration. Supported only for HTTP APIs.</p>
    pub cors_configuration: ::std::option::Option<crate::types::AwsCorsConfiguration>,
}
impl AwsApiGatewayV2ApiDetails {
    /// <p>The URI of the API.</p>
    /// <p>Uses the format <code> <i><api-id></api-id></i>.execute-api.<i><region></region></i>.amazonaws.com</code></p>
    /// <p>The stage name is typically appended to the URI to form a complete path to a deployed API stage.</p>
    pub fn api_endpoint(&self) -> ::std::option::Option<&str> {
        self.api_endpoint.as_deref()
    }
    /// <p>The identifier of the API.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>An API key selection expression. Supported only for WebSocket APIs.</p>
    pub fn api_key_selection_expression(&self) -> ::std::option::Option<&str> {
        self.api_key_selection_expression.as_deref()
    }
    /// <p>Indicates when the API was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn created_date(&self) -> ::std::option::Option<&str> {
        self.created_date.as_deref()
    }
    /// <p>A description of the API.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The version identifier for the API.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The name of the API.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The API protocol for the API.</p>
    /// <p>Valid values: <code>WEBSOCKET</code> | <code>HTTP</code></p>
    pub fn protocol_type(&self) -> ::std::option::Option<&str> {
        self.protocol_type.as_deref()
    }
    /// <p>The route selection expression for the API.</p>
    /// <p>For HTTP APIs, must be <code>${request.method} ${request.path}</code>. This is the default value for HTTP APIs.</p>
    /// <p>For WebSocket APIs, there is no default value.</p>
    pub fn route_selection_expression(&self) -> ::std::option::Option<&str> {
        self.route_selection_expression.as_deref()
    }
    /// <p>A cross-origin resource sharing (CORS) configuration. Supported only for HTTP APIs.</p>
    pub fn cors_configuration(&self) -> ::std::option::Option<&crate::types::AwsCorsConfiguration> {
        self.cors_configuration.as_ref()
    }
}
impl AwsApiGatewayV2ApiDetails {
    /// Creates a new builder-style object to manufacture [`AwsApiGatewayV2ApiDetails`](crate::types::AwsApiGatewayV2ApiDetails).
    pub fn builder() -> crate::types::builders::AwsApiGatewayV2ApiDetailsBuilder {
        crate::types::builders::AwsApiGatewayV2ApiDetailsBuilder::default()
    }
}

/// A builder for [`AwsApiGatewayV2ApiDetails`](crate::types::AwsApiGatewayV2ApiDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsApiGatewayV2ApiDetailsBuilder {
    pub(crate) api_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) api_key_selection_expression: ::std::option::Option<::std::string::String>,
    pub(crate) created_date: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) protocol_type: ::std::option::Option<::std::string::String>,
    pub(crate) route_selection_expression: ::std::option::Option<::std::string::String>,
    pub(crate) cors_configuration: ::std::option::Option<crate::types::AwsCorsConfiguration>,
}
impl AwsApiGatewayV2ApiDetailsBuilder {
    /// <p>The URI of the API.</p>
    /// <p>Uses the format <code> <i><api-id></api-id></i>.execute-api.<i><region></region></i>.amazonaws.com</code></p>
    /// <p>The stage name is typically appended to the URI to form a complete path to a deployed API stage.</p>
    pub fn api_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI of the API.</p>
    /// <p>Uses the format <code> <i><api-id></api-id></i>.execute-api.<i><region></region></i>.amazonaws.com</code></p>
    /// <p>The stage name is typically appended to the URI to form a complete path to a deployed API stage.</p>
    pub fn set_api_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_endpoint = input;
        self
    }
    /// <p>The URI of the API.</p>
    /// <p>Uses the format <code> <i><api-id></api-id></i>.execute-api.<i><region></region></i>.amazonaws.com</code></p>
    /// <p>The stage name is typically appended to the URI to form a complete path to a deployed API stage.</p>
    pub fn get_api_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_endpoint
    }
    /// <p>The identifier of the API.</p>
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the API.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The identifier of the API.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>An API key selection expression. Supported only for WebSocket APIs.</p>
    pub fn api_key_selection_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_key_selection_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An API key selection expression. Supported only for WebSocket APIs.</p>
    pub fn set_api_key_selection_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_key_selection_expression = input;
        self
    }
    /// <p>An API key selection expression. Supported only for WebSocket APIs.</p>
    pub fn get_api_key_selection_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_key_selection_expression
    }
    /// <p>Indicates when the API was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn created_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when the API was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>Indicates when the API was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_date
    }
    /// <p>A description of the API.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the API.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the API.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The version identifier for the API.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version identifier for the API.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version identifier for the API.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The name of the API.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the API.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the API.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The API protocol for the API.</p>
    /// <p>Valid values: <code>WEBSOCKET</code> | <code>HTTP</code></p>
    pub fn protocol_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.protocol_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API protocol for the API.</p>
    /// <p>Valid values: <code>WEBSOCKET</code> | <code>HTTP</code></p>
    pub fn set_protocol_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.protocol_type = input;
        self
    }
    /// <p>The API protocol for the API.</p>
    /// <p>Valid values: <code>WEBSOCKET</code> | <code>HTTP</code></p>
    pub fn get_protocol_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.protocol_type
    }
    /// <p>The route selection expression for the API.</p>
    /// <p>For HTTP APIs, must be <code>${request.method} ${request.path}</code>. This is the default value for HTTP APIs.</p>
    /// <p>For WebSocket APIs, there is no default value.</p>
    pub fn route_selection_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_selection_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The route selection expression for the API.</p>
    /// <p>For HTTP APIs, must be <code>${request.method} ${request.path}</code>. This is the default value for HTTP APIs.</p>
    /// <p>For WebSocket APIs, there is no default value.</p>
    pub fn set_route_selection_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_selection_expression = input;
        self
    }
    /// <p>The route selection expression for the API.</p>
    /// <p>For HTTP APIs, must be <code>${request.method} ${request.path}</code>. This is the default value for HTTP APIs.</p>
    /// <p>For WebSocket APIs, there is no default value.</p>
    pub fn get_route_selection_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_selection_expression
    }
    /// <p>A cross-origin resource sharing (CORS) configuration. Supported only for HTTP APIs.</p>
    pub fn cors_configuration(mut self, input: crate::types::AwsCorsConfiguration) -> Self {
        self.cors_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A cross-origin resource sharing (CORS) configuration. Supported only for HTTP APIs.</p>
    pub fn set_cors_configuration(mut self, input: ::std::option::Option<crate::types::AwsCorsConfiguration>) -> Self {
        self.cors_configuration = input;
        self
    }
    /// <p>A cross-origin resource sharing (CORS) configuration. Supported only for HTTP APIs.</p>
    pub fn get_cors_configuration(&self) -> &::std::option::Option<crate::types::AwsCorsConfiguration> {
        &self.cors_configuration
    }
    /// Consumes the builder and constructs a [`AwsApiGatewayV2ApiDetails`](crate::types::AwsApiGatewayV2ApiDetails).
    pub fn build(self) -> crate::types::AwsApiGatewayV2ApiDetails {
        crate::types::AwsApiGatewayV2ApiDetails {
            api_endpoint: self.api_endpoint,
            api_id: self.api_id,
            api_key_selection_expression: self.api_key_selection_expression,
            created_date: self.created_date,
            description: self.description,
            version: self.version,
            name: self.name,
            protocol_type: self.protocol_type,
            route_selection_expression: self.route_selection_expression,
            cors_configuration: self.cors_configuration,
        }
    }
}
