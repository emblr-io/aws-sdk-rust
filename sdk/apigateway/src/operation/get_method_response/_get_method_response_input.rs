// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to describe a MethodResponse resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMethodResponseInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The Resource identifier for the MethodResponse resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The HTTP verb of the Method resource.</p>
    pub http_method: ::std::option::Option<::std::string::String>,
    /// <p>The status code for the MethodResponse resource.</p>
    pub status_code: ::std::option::Option<::std::string::String>,
}
impl GetMethodResponseInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The Resource identifier for the MethodResponse resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The HTTP verb of the Method resource.</p>
    pub fn http_method(&self) -> ::std::option::Option<&str> {
        self.http_method.as_deref()
    }
    /// <p>The status code for the MethodResponse resource.</p>
    pub fn status_code(&self) -> ::std::option::Option<&str> {
        self.status_code.as_deref()
    }
}
impl GetMethodResponseInput {
    /// Creates a new builder-style object to manufacture [`GetMethodResponseInput`](crate::operation::get_method_response::GetMethodResponseInput).
    pub fn builder() -> crate::operation::get_method_response::builders::GetMethodResponseInputBuilder {
        crate::operation::get_method_response::builders::GetMethodResponseInputBuilder::default()
    }
}

/// A builder for [`GetMethodResponseInput`](crate::operation::get_method_response::GetMethodResponseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMethodResponseInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) http_method: ::std::option::Option<::std::string::String>,
    pub(crate) status_code: ::std::option::Option<::std::string::String>,
}
impl GetMethodResponseInputBuilder {
    /// <p>The string identifier of the associated RestApi.</p>
    /// This field is required.
    pub fn rest_api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rest_api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn set_rest_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rest_api_id = input;
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn get_rest_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rest_api_id
    }
    /// <p>The Resource identifier for the MethodResponse resource.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Resource identifier for the MethodResponse resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The Resource identifier for the MethodResponse resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The HTTP verb of the Method resource.</p>
    /// This field is required.
    pub fn http_method(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.http_method = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP verb of the Method resource.</p>
    pub fn set_http_method(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.http_method = input;
        self
    }
    /// <p>The HTTP verb of the Method resource.</p>
    pub fn get_http_method(&self) -> &::std::option::Option<::std::string::String> {
        &self.http_method
    }
    /// <p>The status code for the MethodResponse resource.</p>
    /// This field is required.
    pub fn status_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status code for the MethodResponse resource.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The status code for the MethodResponse resource.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_code
    }
    /// Consumes the builder and constructs a [`GetMethodResponseInput`](crate::operation::get_method_response::GetMethodResponseInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_method_response::GetMethodResponseInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_method_response::GetMethodResponseInput {
            rest_api_id: self.rest_api_id,
            resource_id: self.resource_id,
            http_method: self.http_method,
            status_code: self.status_code,
        })
    }
}
