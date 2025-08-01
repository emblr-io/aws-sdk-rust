// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRouteInput {
    /// <p>The ID of the environment to delete the route from.</p>
    pub environment_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the application to delete the route from.</p>
    pub application_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the route to delete.</p>
    pub route_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteRouteInput {
    /// <p>The ID of the environment to delete the route from.</p>
    pub fn environment_identifier(&self) -> ::std::option::Option<&str> {
        self.environment_identifier.as_deref()
    }
    /// <p>The ID of the application to delete the route from.</p>
    pub fn application_identifier(&self) -> ::std::option::Option<&str> {
        self.application_identifier.as_deref()
    }
    /// <p>The ID of the route to delete.</p>
    pub fn route_identifier(&self) -> ::std::option::Option<&str> {
        self.route_identifier.as_deref()
    }
}
impl DeleteRouteInput {
    /// Creates a new builder-style object to manufacture [`DeleteRouteInput`](crate::operation::delete_route::DeleteRouteInput).
    pub fn builder() -> crate::operation::delete_route::builders::DeleteRouteInputBuilder {
        crate::operation::delete_route::builders::DeleteRouteInputBuilder::default()
    }
}

/// A builder for [`DeleteRouteInput`](crate::operation::delete_route::DeleteRouteInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRouteInputBuilder {
    pub(crate) environment_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) application_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) route_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteRouteInputBuilder {
    /// <p>The ID of the environment to delete the route from.</p>
    /// This field is required.
    pub fn environment_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the environment to delete the route from.</p>
    pub fn set_environment_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_identifier = input;
        self
    }
    /// <p>The ID of the environment to delete the route from.</p>
    pub fn get_environment_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_identifier
    }
    /// <p>The ID of the application to delete the route from.</p>
    /// This field is required.
    pub fn application_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application to delete the route from.</p>
    pub fn set_application_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_identifier = input;
        self
    }
    /// <p>The ID of the application to delete the route from.</p>
    pub fn get_application_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_identifier
    }
    /// <p>The ID of the route to delete.</p>
    /// This field is required.
    pub fn route_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.route_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the route to delete.</p>
    pub fn set_route_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.route_identifier = input;
        self
    }
    /// <p>The ID of the route to delete.</p>
    pub fn get_route_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.route_identifier
    }
    /// Consumes the builder and constructs a [`DeleteRouteInput`](crate::operation::delete_route::DeleteRouteInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_route::DeleteRouteInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_route::DeleteRouteInput {
            environment_identifier: self.environment_identifier,
            application_identifier: self.application_identifier,
            route_identifier: self.route_identifier,
        })
    }
}
