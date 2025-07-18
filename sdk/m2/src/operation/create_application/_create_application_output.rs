// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateApplicationOutput {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub application_arn: ::std::string::String,
    /// <p>The unique application identifier.</p>
    pub application_id: ::std::string::String,
    /// <p>The version number of the application.</p>
    pub application_version: i32,
    _request_id: Option<String>,
}
impl CreateApplicationOutput {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn application_arn(&self) -> &str {
        use std::ops::Deref;
        self.application_arn.deref()
    }
    /// <p>The unique application identifier.</p>
    pub fn application_id(&self) -> &str {
        use std::ops::Deref;
        self.application_id.deref()
    }
    /// <p>The version number of the application.</p>
    pub fn application_version(&self) -> i32 {
        self.application_version
    }
}
impl ::aws_types::request_id::RequestId for CreateApplicationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateApplicationOutput {
    /// Creates a new builder-style object to manufacture [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    pub fn builder() -> crate::operation::create_application::builders::CreateApplicationOutputBuilder {
        crate::operation::create_application::builders::CreateApplicationOutputBuilder::default()
    }
}

/// A builder for [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateApplicationOutputBuilder {
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) application_version: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl CreateApplicationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    /// This field is required.
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// <p>The unique application identifier.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique application identifier.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The unique application identifier.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The version number of the application.</p>
    /// This field is required.
    pub fn application_version(mut self, input: i32) -> Self {
        self.application_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the application.</p>
    pub fn set_application_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.application_version = input;
        self
    }
    /// <p>The version number of the application.</p>
    pub fn get_application_version(&self) -> &::std::option::Option<i32> {
        &self.application_version
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`application_arn`](crate::operation::create_application::builders::CreateApplicationOutputBuilder::application_arn)
    /// - [`application_id`](crate::operation::create_application::builders::CreateApplicationOutputBuilder::application_id)
    /// - [`application_version`](crate::operation::create_application::builders::CreateApplicationOutputBuilder::application_version)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_application::CreateApplicationOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_application::CreateApplicationOutput {
            application_arn: self.application_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_arn",
                    "application_arn was not specified but it is required when building CreateApplicationOutput",
                )
            })?,
            application_id: self.application_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_id",
                    "application_id was not specified but it is required when building CreateApplicationOutput",
                )
            })?,
            application_version: self.application_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_version",
                    "application_version was not specified but it is required when building CreateApplicationOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
