// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A set of validation rules for incoming Method requests.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRequestValidatorOutput {
    /// <p>The identifier of this RequestValidator.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of this RequestValidator</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A Boolean flag to indicate whether to validate a request body according to the configured Model schema.</p>
    pub validate_request_body: bool,
    /// <p>A Boolean flag to indicate whether to validate request parameters (<code>true</code>) or not (<code>false</code>).</p>
    pub validate_request_parameters: bool,
    _request_id: Option<String>,
}
impl UpdateRequestValidatorOutput {
    /// <p>The identifier of this RequestValidator.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of this RequestValidator</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A Boolean flag to indicate whether to validate a request body according to the configured Model schema.</p>
    pub fn validate_request_body(&self) -> bool {
        self.validate_request_body
    }
    /// <p>A Boolean flag to indicate whether to validate request parameters (<code>true</code>) or not (<code>false</code>).</p>
    pub fn validate_request_parameters(&self) -> bool {
        self.validate_request_parameters
    }
}
impl ::aws_types::request_id::RequestId for UpdateRequestValidatorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateRequestValidatorOutput {
    /// Creates a new builder-style object to manufacture [`UpdateRequestValidatorOutput`](crate::operation::update_request_validator::UpdateRequestValidatorOutput).
    pub fn builder() -> crate::operation::update_request_validator::builders::UpdateRequestValidatorOutputBuilder {
        crate::operation::update_request_validator::builders::UpdateRequestValidatorOutputBuilder::default()
    }
}

/// A builder for [`UpdateRequestValidatorOutput`](crate::operation::update_request_validator::UpdateRequestValidatorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRequestValidatorOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) validate_request_body: ::std::option::Option<bool>,
    pub(crate) validate_request_parameters: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl UpdateRequestValidatorOutputBuilder {
    /// <p>The identifier of this RequestValidator.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of this RequestValidator.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of this RequestValidator.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of this RequestValidator</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of this RequestValidator</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of this RequestValidator</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A Boolean flag to indicate whether to validate a request body according to the configured Model schema.</p>
    pub fn validate_request_body(mut self, input: bool) -> Self {
        self.validate_request_body = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean flag to indicate whether to validate a request body according to the configured Model schema.</p>
    pub fn set_validate_request_body(mut self, input: ::std::option::Option<bool>) -> Self {
        self.validate_request_body = input;
        self
    }
    /// <p>A Boolean flag to indicate whether to validate a request body according to the configured Model schema.</p>
    pub fn get_validate_request_body(&self) -> &::std::option::Option<bool> {
        &self.validate_request_body
    }
    /// <p>A Boolean flag to indicate whether to validate request parameters (<code>true</code>) or not (<code>false</code>).</p>
    pub fn validate_request_parameters(mut self, input: bool) -> Self {
        self.validate_request_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean flag to indicate whether to validate request parameters (<code>true</code>) or not (<code>false</code>).</p>
    pub fn set_validate_request_parameters(mut self, input: ::std::option::Option<bool>) -> Self {
        self.validate_request_parameters = input;
        self
    }
    /// <p>A Boolean flag to indicate whether to validate request parameters (<code>true</code>) or not (<code>false</code>).</p>
    pub fn get_validate_request_parameters(&self) -> &::std::option::Option<bool> {
        &self.validate_request_parameters
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateRequestValidatorOutput`](crate::operation::update_request_validator::UpdateRequestValidatorOutput).
    pub fn build(self) -> crate::operation::update_request_validator::UpdateRequestValidatorOutput {
        crate::operation::update_request_validator::UpdateRequestValidatorOutput {
            id: self.id,
            name: self.name,
            validate_request_body: self.validate_request_body.unwrap_or_default(),
            validate_request_parameters: self.validate_request_parameters.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}
