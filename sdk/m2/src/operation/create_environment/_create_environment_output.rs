// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEnvironmentOutput {
    /// <p>The unique identifier of the runtime environment.</p>
    pub environment_id: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateEnvironmentOutput {
    /// <p>The unique identifier of the runtime environment.</p>
    pub fn environment_id(&self) -> &str {
        use std::ops::Deref;
        self.environment_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEnvironmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEnvironmentOutput {
    /// Creates a new builder-style object to manufacture [`CreateEnvironmentOutput`](crate::operation::create_environment::CreateEnvironmentOutput).
    pub fn builder() -> crate::operation::create_environment::builders::CreateEnvironmentOutputBuilder {
        crate::operation::create_environment::builders::CreateEnvironmentOutputBuilder::default()
    }
}

/// A builder for [`CreateEnvironmentOutput`](crate::operation::create_environment::CreateEnvironmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEnvironmentOutputBuilder {
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateEnvironmentOutputBuilder {
    /// <p>The unique identifier of the runtime environment.</p>
    /// This field is required.
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the runtime environment.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>The unique identifier of the runtime environment.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEnvironmentOutput`](crate::operation::create_environment::CreateEnvironmentOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`environment_id`](crate::operation::create_environment::builders::CreateEnvironmentOutputBuilder::environment_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_environment::CreateEnvironmentOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_environment::CreateEnvironmentOutput {
            environment_id: self.environment_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "environment_id",
                    "environment_id was not specified but it is required when building CreateEnvironmentOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
