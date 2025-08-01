// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a client-facing interface by which the client calls the API to access back-end resources. A Method resource is integrated with an Integration resource. Both consist of a request and one or more responses. The method request takes the client input that is passed to the back end through the integration request. A method response returns the output from the back end to the client through an integration response. A method request is embodied in a Method resource, whereas an integration request is embodied in an Integration resource. On the other hand, a method response is represented by a MethodResponse resource, whereas an integration response is represented by an IntegrationResponse resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateMethodOutput {
    /// <p>The method's HTTP verb.</p>
    pub http_method: ::std::option::Option<::std::string::String>,
    /// <p>The method's authorization type. Valid values are <code>NONE</code> for open access, <code>AWS_IAM</code> for using AWS IAM permissions, <code>CUSTOM</code> for using a custom authorizer, or <code>COGNITO_USER_POOLS</code> for using a Cognito user pool.</p>
    pub authorization_type: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of an Authorizer to use on this method. The <code>authorizationType</code> must be <code>CUSTOM</code>.</p>
    pub authorizer_id: ::std::option::Option<::std::string::String>,
    /// <p>A boolean flag specifying whether a valid ApiKey is required to invoke this method.</p>
    pub api_key_required: ::std::option::Option<bool>,
    /// <p>The identifier of a RequestValidator for request validation.</p>
    pub request_validator_id: ::std::option::Option<::std::string::String>,
    /// <p>A human-friendly operation identifier for the method. For example, you can assign the <code>operationName</code> of <code>ListPets</code> for the <code>GET /pets</code> method in the <code>PetStore</code> example.</p>
    pub operation_name: ::std::option::Option<::std::string::String>,
    /// <p>A key-value map defining required or optional method request parameters that can be accepted by API Gateway. A key is a method request parameter name matching the pattern of <code>method.request.{location}.{name}</code>, where <code>location</code> is <code>querystring</code>, <code>path</code>, or <code>header</code> and <code>name</code> is a valid and unique parameter name. The value associated with the key is a Boolean flag indicating whether the parameter is required (<code>true</code>) or optional (<code>false</code>). The method request parameter names defined here are available in Integration to be mapped to integration request parameters or templates.</p>
    pub request_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, bool>>,
    /// <p>A key-value map specifying data schemas, represented by Model resources, (as the mapped value) of the request payloads of given content types (as the mapping key).</p>
    pub request_models: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Gets a method response associated with a given HTTP status code.</p>
    pub method_responses: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MethodResponse>>,
    /// <p>Gets the method's integration responsible for passing the client-submitted request to the back end and performing necessary transformations to make the request compliant with the back end.</p>
    pub method_integration: ::std::option::Option<crate::types::Integration>,
    /// <p>A list of authorization scopes configured on the method. The scopes are used with a <code>COGNITO_USER_POOLS</code> authorizer to authorize the method invocation. The authorization works by matching the method scopes against the scopes parsed from the access token in the incoming request. The method invocation is authorized if any method scopes matches a claimed scope in the access token. Otherwise, the invocation is not authorized. When the method scope is configured, the client must provide an access token instead of an identity token for authorization purposes.</p>
    pub authorization_scopes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateMethodOutput {
    /// <p>The method's HTTP verb.</p>
    pub fn http_method(&self) -> ::std::option::Option<&str> {
        self.http_method.as_deref()
    }
    /// <p>The method's authorization type. Valid values are <code>NONE</code> for open access, <code>AWS_IAM</code> for using AWS IAM permissions, <code>CUSTOM</code> for using a custom authorizer, or <code>COGNITO_USER_POOLS</code> for using a Cognito user pool.</p>
    pub fn authorization_type(&self) -> ::std::option::Option<&str> {
        self.authorization_type.as_deref()
    }
    /// <p>The identifier of an Authorizer to use on this method. The <code>authorizationType</code> must be <code>CUSTOM</code>.</p>
    pub fn authorizer_id(&self) -> ::std::option::Option<&str> {
        self.authorizer_id.as_deref()
    }
    /// <p>A boolean flag specifying whether a valid ApiKey is required to invoke this method.</p>
    pub fn api_key_required(&self) -> ::std::option::Option<bool> {
        self.api_key_required
    }
    /// <p>The identifier of a RequestValidator for request validation.</p>
    pub fn request_validator_id(&self) -> ::std::option::Option<&str> {
        self.request_validator_id.as_deref()
    }
    /// <p>A human-friendly operation identifier for the method. For example, you can assign the <code>operationName</code> of <code>ListPets</code> for the <code>GET /pets</code> method in the <code>PetStore</code> example.</p>
    pub fn operation_name(&self) -> ::std::option::Option<&str> {
        self.operation_name.as_deref()
    }
    /// <p>A key-value map defining required or optional method request parameters that can be accepted by API Gateway. A key is a method request parameter name matching the pattern of <code>method.request.{location}.{name}</code>, where <code>location</code> is <code>querystring</code>, <code>path</code>, or <code>header</code> and <code>name</code> is a valid and unique parameter name. The value associated with the key is a Boolean flag indicating whether the parameter is required (<code>true</code>) or optional (<code>false</code>). The method request parameter names defined here are available in Integration to be mapped to integration request parameters or templates.</p>
    pub fn request_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, bool>> {
        self.request_parameters.as_ref()
    }
    /// <p>A key-value map specifying data schemas, represented by Model resources, (as the mapped value) of the request payloads of given content types (as the mapping key).</p>
    pub fn request_models(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.request_models.as_ref()
    }
    /// <p>Gets a method response associated with a given HTTP status code.</p>
    pub fn method_responses(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::MethodResponse>> {
        self.method_responses.as_ref()
    }
    /// <p>Gets the method's integration responsible for passing the client-submitted request to the back end and performing necessary transformations to make the request compliant with the back end.</p>
    pub fn method_integration(&self) -> ::std::option::Option<&crate::types::Integration> {
        self.method_integration.as_ref()
    }
    /// <p>A list of authorization scopes configured on the method. The scopes are used with a <code>COGNITO_USER_POOLS</code> authorizer to authorize the method invocation. The authorization works by matching the method scopes against the scopes parsed from the access token in the incoming request. The method invocation is authorized if any method scopes matches a claimed scope in the access token. Otherwise, the invocation is not authorized. When the method scope is configured, the client must provide an access token instead of an identity token for authorization purposes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.authorization_scopes.is_none()`.
    pub fn authorization_scopes(&self) -> &[::std::string::String] {
        self.authorization_scopes.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for UpdateMethodOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateMethodOutput {
    /// Creates a new builder-style object to manufacture [`UpdateMethodOutput`](crate::operation::update_method::UpdateMethodOutput).
    pub fn builder() -> crate::operation::update_method::builders::UpdateMethodOutputBuilder {
        crate::operation::update_method::builders::UpdateMethodOutputBuilder::default()
    }
}

/// A builder for [`UpdateMethodOutput`](crate::operation::update_method::UpdateMethodOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateMethodOutputBuilder {
    pub(crate) http_method: ::std::option::Option<::std::string::String>,
    pub(crate) authorization_type: ::std::option::Option<::std::string::String>,
    pub(crate) authorizer_id: ::std::option::Option<::std::string::String>,
    pub(crate) api_key_required: ::std::option::Option<bool>,
    pub(crate) request_validator_id: ::std::option::Option<::std::string::String>,
    pub(crate) operation_name: ::std::option::Option<::std::string::String>,
    pub(crate) request_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, bool>>,
    pub(crate) request_models: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) method_responses: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MethodResponse>>,
    pub(crate) method_integration: ::std::option::Option<crate::types::Integration>,
    pub(crate) authorization_scopes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateMethodOutputBuilder {
    /// <p>The method's HTTP verb.</p>
    pub fn http_method(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.http_method = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The method's HTTP verb.</p>
    pub fn set_http_method(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.http_method = input;
        self
    }
    /// <p>The method's HTTP verb.</p>
    pub fn get_http_method(&self) -> &::std::option::Option<::std::string::String> {
        &self.http_method
    }
    /// <p>The method's authorization type. Valid values are <code>NONE</code> for open access, <code>AWS_IAM</code> for using AWS IAM permissions, <code>CUSTOM</code> for using a custom authorizer, or <code>COGNITO_USER_POOLS</code> for using a Cognito user pool.</p>
    pub fn authorization_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorization_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The method's authorization type. Valid values are <code>NONE</code> for open access, <code>AWS_IAM</code> for using AWS IAM permissions, <code>CUSTOM</code> for using a custom authorizer, or <code>COGNITO_USER_POOLS</code> for using a Cognito user pool.</p>
    pub fn set_authorization_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorization_type = input;
        self
    }
    /// <p>The method's authorization type. Valid values are <code>NONE</code> for open access, <code>AWS_IAM</code> for using AWS IAM permissions, <code>CUSTOM</code> for using a custom authorizer, or <code>COGNITO_USER_POOLS</code> for using a Cognito user pool.</p>
    pub fn get_authorization_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorization_type
    }
    /// <p>The identifier of an Authorizer to use on this method. The <code>authorizationType</code> must be <code>CUSTOM</code>.</p>
    pub fn authorizer_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorizer_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of an Authorizer to use on this method. The <code>authorizationType</code> must be <code>CUSTOM</code>.</p>
    pub fn set_authorizer_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorizer_id = input;
        self
    }
    /// <p>The identifier of an Authorizer to use on this method. The <code>authorizationType</code> must be <code>CUSTOM</code>.</p>
    pub fn get_authorizer_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorizer_id
    }
    /// <p>A boolean flag specifying whether a valid ApiKey is required to invoke this method.</p>
    pub fn api_key_required(mut self, input: bool) -> Self {
        self.api_key_required = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean flag specifying whether a valid ApiKey is required to invoke this method.</p>
    pub fn set_api_key_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.api_key_required = input;
        self
    }
    /// <p>A boolean flag specifying whether a valid ApiKey is required to invoke this method.</p>
    pub fn get_api_key_required(&self) -> &::std::option::Option<bool> {
        &self.api_key_required
    }
    /// <p>The identifier of a RequestValidator for request validation.</p>
    pub fn request_validator_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_validator_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of a RequestValidator for request validation.</p>
    pub fn set_request_validator_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_validator_id = input;
        self
    }
    /// <p>The identifier of a RequestValidator for request validation.</p>
    pub fn get_request_validator_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_validator_id
    }
    /// <p>A human-friendly operation identifier for the method. For example, you can assign the <code>operationName</code> of <code>ListPets</code> for the <code>GET /pets</code> method in the <code>PetStore</code> example.</p>
    pub fn operation_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A human-friendly operation identifier for the method. For example, you can assign the <code>operationName</code> of <code>ListPets</code> for the <code>GET /pets</code> method in the <code>PetStore</code> example.</p>
    pub fn set_operation_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_name = input;
        self
    }
    /// <p>A human-friendly operation identifier for the method. For example, you can assign the <code>operationName</code> of <code>ListPets</code> for the <code>GET /pets</code> method in the <code>PetStore</code> example.</p>
    pub fn get_operation_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_name
    }
    /// Adds a key-value pair to `request_parameters`.
    ///
    /// To override the contents of this collection use [`set_request_parameters`](Self::set_request_parameters).
    ///
    /// <p>A key-value map defining required or optional method request parameters that can be accepted by API Gateway. A key is a method request parameter name matching the pattern of <code>method.request.{location}.{name}</code>, where <code>location</code> is <code>querystring</code>, <code>path</code>, or <code>header</code> and <code>name</code> is a valid and unique parameter name. The value associated with the key is a Boolean flag indicating whether the parameter is required (<code>true</code>) or optional (<code>false</code>). The method request parameter names defined here are available in Integration to be mapped to integration request parameters or templates.</p>
    pub fn request_parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: bool) -> Self {
        let mut hash_map = self.request_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.request_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A key-value map defining required or optional method request parameters that can be accepted by API Gateway. A key is a method request parameter name matching the pattern of <code>method.request.{location}.{name}</code>, where <code>location</code> is <code>querystring</code>, <code>path</code>, or <code>header</code> and <code>name</code> is a valid and unique parameter name. The value associated with the key is a Boolean flag indicating whether the parameter is required (<code>true</code>) or optional (<code>false</code>). The method request parameter names defined here are available in Integration to be mapped to integration request parameters or templates.</p>
    pub fn set_request_parameters(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, bool>>) -> Self {
        self.request_parameters = input;
        self
    }
    /// <p>A key-value map defining required or optional method request parameters that can be accepted by API Gateway. A key is a method request parameter name matching the pattern of <code>method.request.{location}.{name}</code>, where <code>location</code> is <code>querystring</code>, <code>path</code>, or <code>header</code> and <code>name</code> is a valid and unique parameter name. The value associated with the key is a Boolean flag indicating whether the parameter is required (<code>true</code>) or optional (<code>false</code>). The method request parameter names defined here are available in Integration to be mapped to integration request parameters or templates.</p>
    pub fn get_request_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, bool>> {
        &self.request_parameters
    }
    /// Adds a key-value pair to `request_models`.
    ///
    /// To override the contents of this collection use [`set_request_models`](Self::set_request_models).
    ///
    /// <p>A key-value map specifying data schemas, represented by Model resources, (as the mapped value) of the request payloads of given content types (as the mapping key).</p>
    pub fn request_models(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.request_models.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.request_models = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A key-value map specifying data schemas, represented by Model resources, (as the mapped value) of the request payloads of given content types (as the mapping key).</p>
    pub fn set_request_models(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.request_models = input;
        self
    }
    /// <p>A key-value map specifying data schemas, represented by Model resources, (as the mapped value) of the request payloads of given content types (as the mapping key).</p>
    pub fn get_request_models(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.request_models
    }
    /// Adds a key-value pair to `method_responses`.
    ///
    /// To override the contents of this collection use [`set_method_responses`](Self::set_method_responses).
    ///
    /// <p>Gets a method response associated with a given HTTP status code.</p>
    pub fn method_responses(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::MethodResponse) -> Self {
        let mut hash_map = self.method_responses.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.method_responses = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Gets a method response associated with a given HTTP status code.</p>
    pub fn set_method_responses(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MethodResponse>>,
    ) -> Self {
        self.method_responses = input;
        self
    }
    /// <p>Gets a method response associated with a given HTTP status code.</p>
    pub fn get_method_responses(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MethodResponse>> {
        &self.method_responses
    }
    /// <p>Gets the method's integration responsible for passing the client-submitted request to the back end and performing necessary transformations to make the request compliant with the back end.</p>
    pub fn method_integration(mut self, input: crate::types::Integration) -> Self {
        self.method_integration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Gets the method's integration responsible for passing the client-submitted request to the back end and performing necessary transformations to make the request compliant with the back end.</p>
    pub fn set_method_integration(mut self, input: ::std::option::Option<crate::types::Integration>) -> Self {
        self.method_integration = input;
        self
    }
    /// <p>Gets the method's integration responsible for passing the client-submitted request to the back end and performing necessary transformations to make the request compliant with the back end.</p>
    pub fn get_method_integration(&self) -> &::std::option::Option<crate::types::Integration> {
        &self.method_integration
    }
    /// Appends an item to `authorization_scopes`.
    ///
    /// To override the contents of this collection use [`set_authorization_scopes`](Self::set_authorization_scopes).
    ///
    /// <p>A list of authorization scopes configured on the method. The scopes are used with a <code>COGNITO_USER_POOLS</code> authorizer to authorize the method invocation. The authorization works by matching the method scopes against the scopes parsed from the access token in the incoming request. The method invocation is authorized if any method scopes matches a claimed scope in the access token. Otherwise, the invocation is not authorized. When the method scope is configured, the client must provide an access token instead of an identity token for authorization purposes.</p>
    pub fn authorization_scopes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.authorization_scopes.unwrap_or_default();
        v.push(input.into());
        self.authorization_scopes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of authorization scopes configured on the method. The scopes are used with a <code>COGNITO_USER_POOLS</code> authorizer to authorize the method invocation. The authorization works by matching the method scopes against the scopes parsed from the access token in the incoming request. The method invocation is authorized if any method scopes matches a claimed scope in the access token. Otherwise, the invocation is not authorized. When the method scope is configured, the client must provide an access token instead of an identity token for authorization purposes.</p>
    pub fn set_authorization_scopes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.authorization_scopes = input;
        self
    }
    /// <p>A list of authorization scopes configured on the method. The scopes are used with a <code>COGNITO_USER_POOLS</code> authorizer to authorize the method invocation. The authorization works by matching the method scopes against the scopes parsed from the access token in the incoming request. The method invocation is authorized if any method scopes matches a claimed scope in the access token. Otherwise, the invocation is not authorized. When the method scope is configured, the client must provide an access token instead of an identity token for authorization purposes.</p>
    pub fn get_authorization_scopes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.authorization_scopes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateMethodOutput`](crate::operation::update_method::UpdateMethodOutput).
    pub fn build(self) -> crate::operation::update_method::UpdateMethodOutput {
        crate::operation::update_method::UpdateMethodOutput {
            http_method: self.http_method,
            authorization_type: self.authorization_type,
            authorizer_id: self.authorizer_id,
            api_key_required: self.api_key_required,
            request_validator_id: self.request_validator_id,
            operation_name: self.operation_name,
            request_parameters: self.request_parameters,
            request_models: self.request_models,
            method_responses: self.method_responses,
            method_integration: self.method_integration,
            authorization_scopes: self.authorization_scopes,
            _request_id: self._request_id,
        }
    }
}
