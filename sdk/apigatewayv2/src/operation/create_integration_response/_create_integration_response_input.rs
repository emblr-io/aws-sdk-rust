// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Creates a new IntegrationResponse resource to represent an integration response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateIntegrationResponseInput {
    /// <p>The API identifier.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies how to handle response payload content type conversions. Supported values are CONVERT_TO_BINARY and CONVERT_TO_TEXT, with the following behaviors:</p>
    /// <p>CONVERT_TO_BINARY: Converts a response payload from a Base64-encoded string to the corresponding binary blob.</p>
    /// <p>CONVERT_TO_TEXT: Converts a response payload from a binary blob to a Base64-encoded string.</p>
    /// <p>If this property is not defined, the response payload will be passed through from the integration response to the route response or method response without modification.</p>
    pub content_handling_strategy: ::std::option::Option<crate::types::ContentHandlingStrategy>,
    /// <p>The integration ID.</p>
    pub integration_id: ::std::option::Option<::std::string::String>,
    /// <p>The integration response key.</p>
    pub integration_response_key: ::std::option::Option<::std::string::String>,
    /// <p>A key-value map specifying response parameters that are passed to the method response from the backend. The key is a method response header parameter name and the mapped value is an integration response header value, a static value enclosed within a pair of single quotes, or a JSON expression from the integration response body. The mapping key must match the pattern of method.response.header.{name}, where {name} is a valid and unique header name. The mapped non-static value must match the pattern of integration.response.header.{name} or integration.response.body.{JSON-expression}, where {name} is a valid and unique response header name and {JSON-expression} is a valid JSON expression without the $ prefix.</p>
    pub response_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The collection of response templates for the integration response as a string-to-string map of key-value pairs. Response templates are represented as a key/value map, with a content-type as the key and a template as the value.</p>
    pub response_templates: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The template selection expression for the integration response. Supported only for WebSocket APIs.</p>
    pub template_selection_expression: ::std::option::Option<::std::string::String>,
}
impl CreateIntegrationResponseInput {
    /// <p>The API identifier.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>Specifies how to handle response payload content type conversions. Supported values are CONVERT_TO_BINARY and CONVERT_TO_TEXT, with the following behaviors:</p>
    /// <p>CONVERT_TO_BINARY: Converts a response payload from a Base64-encoded string to the corresponding binary blob.</p>
    /// <p>CONVERT_TO_TEXT: Converts a response payload from a binary blob to a Base64-encoded string.</p>
    /// <p>If this property is not defined, the response payload will be passed through from the integration response to the route response or method response without modification.</p>
    pub fn content_handling_strategy(&self) -> ::std::option::Option<&crate::types::ContentHandlingStrategy> {
        self.content_handling_strategy.as_ref()
    }
    /// <p>The integration ID.</p>
    pub fn integration_id(&self) -> ::std::option::Option<&str> {
        self.integration_id.as_deref()
    }
    /// <p>The integration response key.</p>
    pub fn integration_response_key(&self) -> ::std::option::Option<&str> {
        self.integration_response_key.as_deref()
    }
    /// <p>A key-value map specifying response parameters that are passed to the method response from the backend. The key is a method response header parameter name and the mapped value is an integration response header value, a static value enclosed within a pair of single quotes, or a JSON expression from the integration response body. The mapping key must match the pattern of method.response.header.{name}, where {name} is a valid and unique header name. The mapped non-static value must match the pattern of integration.response.header.{name} or integration.response.body.{JSON-expression}, where {name} is a valid and unique response header name and {JSON-expression} is a valid JSON expression without the $ prefix.</p>
    pub fn response_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.response_parameters.as_ref()
    }
    /// <p>The collection of response templates for the integration response as a string-to-string map of key-value pairs. Response templates are represented as a key/value map, with a content-type as the key and a template as the value.</p>
    pub fn response_templates(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.response_templates.as_ref()
    }
    /// <p>The template selection expression for the integration response. Supported only for WebSocket APIs.</p>
    pub fn template_selection_expression(&self) -> ::std::option::Option<&str> {
        self.template_selection_expression.as_deref()
    }
}
impl CreateIntegrationResponseInput {
    /// Creates a new builder-style object to manufacture [`CreateIntegrationResponseInput`](crate::operation::create_integration_response::CreateIntegrationResponseInput).
    pub fn builder() -> crate::operation::create_integration_response::builders::CreateIntegrationResponseInputBuilder {
        crate::operation::create_integration_response::builders::CreateIntegrationResponseInputBuilder::default()
    }
}

/// A builder for [`CreateIntegrationResponseInput`](crate::operation::create_integration_response::CreateIntegrationResponseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateIntegrationResponseInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) content_handling_strategy: ::std::option::Option<crate::types::ContentHandlingStrategy>,
    pub(crate) integration_id: ::std::option::Option<::std::string::String>,
    pub(crate) integration_response_key: ::std::option::Option<::std::string::String>,
    pub(crate) response_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) response_templates: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) template_selection_expression: ::std::option::Option<::std::string::String>,
}
impl CreateIntegrationResponseInputBuilder {
    /// <p>The API identifier.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API identifier.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The API identifier.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>Specifies how to handle response payload content type conversions. Supported values are CONVERT_TO_BINARY and CONVERT_TO_TEXT, with the following behaviors:</p>
    /// <p>CONVERT_TO_BINARY: Converts a response payload from a Base64-encoded string to the corresponding binary blob.</p>
    /// <p>CONVERT_TO_TEXT: Converts a response payload from a binary blob to a Base64-encoded string.</p>
    /// <p>If this property is not defined, the response payload will be passed through from the integration response to the route response or method response without modification.</p>
    pub fn content_handling_strategy(mut self, input: crate::types::ContentHandlingStrategy) -> Self {
        self.content_handling_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies how to handle response payload content type conversions. Supported values are CONVERT_TO_BINARY and CONVERT_TO_TEXT, with the following behaviors:</p>
    /// <p>CONVERT_TO_BINARY: Converts a response payload from a Base64-encoded string to the corresponding binary blob.</p>
    /// <p>CONVERT_TO_TEXT: Converts a response payload from a binary blob to a Base64-encoded string.</p>
    /// <p>If this property is not defined, the response payload will be passed through from the integration response to the route response or method response without modification.</p>
    pub fn set_content_handling_strategy(mut self, input: ::std::option::Option<crate::types::ContentHandlingStrategy>) -> Self {
        self.content_handling_strategy = input;
        self
    }
    /// <p>Specifies how to handle response payload content type conversions. Supported values are CONVERT_TO_BINARY and CONVERT_TO_TEXT, with the following behaviors:</p>
    /// <p>CONVERT_TO_BINARY: Converts a response payload from a Base64-encoded string to the corresponding binary blob.</p>
    /// <p>CONVERT_TO_TEXT: Converts a response payload from a binary blob to a Base64-encoded string.</p>
    /// <p>If this property is not defined, the response payload will be passed through from the integration response to the route response or method response without modification.</p>
    pub fn get_content_handling_strategy(&self) -> &::std::option::Option<crate::types::ContentHandlingStrategy> {
        &self.content_handling_strategy
    }
    /// <p>The integration ID.</p>
    /// This field is required.
    pub fn integration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.integration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The integration ID.</p>
    pub fn set_integration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.integration_id = input;
        self
    }
    /// <p>The integration ID.</p>
    pub fn get_integration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.integration_id
    }
    /// <p>The integration response key.</p>
    /// This field is required.
    pub fn integration_response_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.integration_response_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The integration response key.</p>
    pub fn set_integration_response_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.integration_response_key = input;
        self
    }
    /// <p>The integration response key.</p>
    pub fn get_integration_response_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.integration_response_key
    }
    /// Adds a key-value pair to `response_parameters`.
    ///
    /// To override the contents of this collection use [`set_response_parameters`](Self::set_response_parameters).
    ///
    /// <p>A key-value map specifying response parameters that are passed to the method response from the backend. The key is a method response header parameter name and the mapped value is an integration response header value, a static value enclosed within a pair of single quotes, or a JSON expression from the integration response body. The mapping key must match the pattern of method.response.header.{name}, where {name} is a valid and unique header name. The mapped non-static value must match the pattern of integration.response.header.{name} or integration.response.body.{JSON-expression}, where {name} is a valid and unique response header name and {JSON-expression} is a valid JSON expression without the $ prefix.</p>
    pub fn response_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.response_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.response_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A key-value map specifying response parameters that are passed to the method response from the backend. The key is a method response header parameter name and the mapped value is an integration response header value, a static value enclosed within a pair of single quotes, or a JSON expression from the integration response body. The mapping key must match the pattern of method.response.header.{name}, where {name} is a valid and unique header name. The mapped non-static value must match the pattern of integration.response.header.{name} or integration.response.body.{JSON-expression}, where {name} is a valid and unique response header name and {JSON-expression} is a valid JSON expression without the $ prefix.</p>
    pub fn set_response_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.response_parameters = input;
        self
    }
    /// <p>A key-value map specifying response parameters that are passed to the method response from the backend. The key is a method response header parameter name and the mapped value is an integration response header value, a static value enclosed within a pair of single quotes, or a JSON expression from the integration response body. The mapping key must match the pattern of method.response.header.{name}, where {name} is a valid and unique header name. The mapped non-static value must match the pattern of integration.response.header.{name} or integration.response.body.{JSON-expression}, where {name} is a valid and unique response header name and {JSON-expression} is a valid JSON expression without the $ prefix.</p>
    pub fn get_response_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.response_parameters
    }
    /// Adds a key-value pair to `response_templates`.
    ///
    /// To override the contents of this collection use [`set_response_templates`](Self::set_response_templates).
    ///
    /// <p>The collection of response templates for the integration response as a string-to-string map of key-value pairs. Response templates are represented as a key/value map, with a content-type as the key and a template as the value.</p>
    pub fn response_templates(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.response_templates.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.response_templates = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The collection of response templates for the integration response as a string-to-string map of key-value pairs. Response templates are represented as a key/value map, with a content-type as the key and a template as the value.</p>
    pub fn set_response_templates(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.response_templates = input;
        self
    }
    /// <p>The collection of response templates for the integration response as a string-to-string map of key-value pairs. Response templates are represented as a key/value map, with a content-type as the key and a template as the value.</p>
    pub fn get_response_templates(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.response_templates
    }
    /// <p>The template selection expression for the integration response. Supported only for WebSocket APIs.</p>
    pub fn template_selection_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_selection_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The template selection expression for the integration response. Supported only for WebSocket APIs.</p>
    pub fn set_template_selection_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_selection_expression = input;
        self
    }
    /// <p>The template selection expression for the integration response. Supported only for WebSocket APIs.</p>
    pub fn get_template_selection_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_selection_expression
    }
    /// Consumes the builder and constructs a [`CreateIntegrationResponseInput`](crate::operation::create_integration_response::CreateIntegrationResponseInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_integration_response::CreateIntegrationResponseInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_integration_response::CreateIntegrationResponseInput {
            api_id: self.api_id,
            content_handling_strategy: self.content_handling_strategy,
            integration_id: self.integration_id,
            integration_response_key: self.integration_response_key,
            response_parameters: self.response_parameters,
            response_templates: self.response_templates,
            template_selection_expression: self.template_selection_expression,
        })
    }
}
