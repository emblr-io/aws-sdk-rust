// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopAccessLoggingInput {
    /// <p>The name of the container that you want to stop access logging on.</p>
    pub container_name: ::std::option::Option<::std::string::String>,
}
impl StopAccessLoggingInput {
    /// <p>The name of the container that you want to stop access logging on.</p>
    pub fn container_name(&self) -> ::std::option::Option<&str> {
        self.container_name.as_deref()
    }
}
impl StopAccessLoggingInput {
    /// Creates a new builder-style object to manufacture [`StopAccessLoggingInput`](crate::operation::stop_access_logging::StopAccessLoggingInput).
    pub fn builder() -> crate::operation::stop_access_logging::builders::StopAccessLoggingInputBuilder {
        crate::operation::stop_access_logging::builders::StopAccessLoggingInputBuilder::default()
    }
}

/// A builder for [`StopAccessLoggingInput`](crate::operation::stop_access_logging::StopAccessLoggingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopAccessLoggingInputBuilder {
    pub(crate) container_name: ::std::option::Option<::std::string::String>,
}
impl StopAccessLoggingInputBuilder {
    /// <p>The name of the container that you want to stop access logging on.</p>
    /// This field is required.
    pub fn container_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container that you want to stop access logging on.</p>
    pub fn set_container_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_name = input;
        self
    }
    /// <p>The name of the container that you want to stop access logging on.</p>
    pub fn get_container_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_name
    }
    /// Consumes the builder and constructs a [`StopAccessLoggingInput`](crate::operation::stop_access_logging::StopAccessLoggingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_access_logging::StopAccessLoggingInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_access_logging::StopAccessLoggingInput {
            container_name: self.container_name,
        })
    }
}
