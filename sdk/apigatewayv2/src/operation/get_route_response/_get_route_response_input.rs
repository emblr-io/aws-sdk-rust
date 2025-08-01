// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRouteResponseInput {
    /// <p>The API identifier.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>The route ID.</p>
    pub route_id: ::std::option::Option<::std::string::String>,
    /// <p>The route response ID.</p>
    pub route_response_id: ::std::option::Option<::std::string::String>,
}
impl GetRouteResponseInput {
    /// <p>The API identifier.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>The route ID.</p>
    pub fn route_id(&self) -> ::std::option::Option<&str> {
        self.route_id.as_deref()
    }
    /// <p>The route response ID.</p>
    pub fn route_response_id(&self) -> ::std::option::Option<&str> {
        self.route_response_id.as_deref()
    }
}
impl GetRouteResponseInput {
    /// Creates a new builder-style object to manufacture [`GetRouteResponseInput`](crate::operation::get_route_response::GetRouteResponseInput).
    pub fn builder() -> crate::operation::get_route_response::builders::GetRouteResponseInputBuilder {
        crate::operation::get_route_response::builders::GetRouteResponseInputBuilder::default()
    }
}

/// A builder for [`GetRouteResponseInput`](crate::operation::get_route_response::GetRouteResponseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRouteResponseInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) route_id: ::std::option::Option<::std::string::String>,
    pub(crate) route_response_id: ::std::option::Option<::std::string::String>,
}
impl GetRouteResponseInputBuilder {
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
    /// <p>The route ID.</p>
    /// This field is required.
    pub fn route_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The route ID.</p>
    pub fn set_route_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_id = input;
        self
    }
    /// <p>The route ID.</p>
    pub fn get_route_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_id
    }
    /// <p>The route response ID.</p>
    /// This field is required.
    pub fn route_response_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_response_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The route response ID.</p>
    pub fn set_route_response_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_response_id = input;
        self
    }
    /// <p>The route response ID.</p>
    pub fn get_route_response_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_response_id
    }
    /// Consumes the builder and constructs a [`GetRouteResponseInput`](crate::operation::get_route_response::GetRouteResponseInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_route_response::GetRouteResponseInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_route_response::GetRouteResponseInput {
            api_id: self.api_id,
            route_id: self.route_id,
            route_response_id: self.route_response_id,
        })
    }
}
