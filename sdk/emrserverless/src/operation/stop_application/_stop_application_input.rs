// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopApplicationInput {
    /// <p>The ID of the application to stop.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
}
impl StopApplicationInput {
    /// <p>The ID of the application to stop.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
}
impl StopApplicationInput {
    /// Creates a new builder-style object to manufacture [`StopApplicationInput`](crate::operation::stop_application::StopApplicationInput).
    pub fn builder() -> crate::operation::stop_application::builders::StopApplicationInputBuilder {
        crate::operation::stop_application::builders::StopApplicationInputBuilder::default()
    }
}

/// A builder for [`StopApplicationInput`](crate::operation::stop_application::StopApplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopApplicationInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
}
impl StopApplicationInputBuilder {
    /// <p>The ID of the application to stop.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application to stop.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The ID of the application to stop.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// Consumes the builder and constructs a [`StopApplicationInput`](crate::operation::stop_application::StopApplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_application::StopApplicationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_application::StopApplicationInput {
            application_id: self.application_id,
        })
    }
}
