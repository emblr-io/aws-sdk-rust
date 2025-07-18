// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartQAppSessionOutput {
    /// <p>The unique identifier of the new or retrieved Q App session.</p>
    pub session_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the new Q App session.</p>
    pub session_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl StartQAppSessionOutput {
    /// <p>The unique identifier of the new or retrieved Q App session.</p>
    pub fn session_id(&self) -> &str {
        use std::ops::Deref;
        self.session_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the new Q App session.</p>
    pub fn session_arn(&self) -> &str {
        use std::ops::Deref;
        self.session_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for StartQAppSessionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartQAppSessionOutput {
    /// Creates a new builder-style object to manufacture [`StartQAppSessionOutput`](crate::operation::start_q_app_session::StartQAppSessionOutput).
    pub fn builder() -> crate::operation::start_q_app_session::builders::StartQAppSessionOutputBuilder {
        crate::operation::start_q_app_session::builders::StartQAppSessionOutputBuilder::default()
    }
}

/// A builder for [`StartQAppSessionOutput`](crate::operation::start_q_app_session::StartQAppSessionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartQAppSessionOutputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) session_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartQAppSessionOutputBuilder {
    /// <p>The unique identifier of the new or retrieved Q App session.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the new or retrieved Q App session.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The unique identifier of the new or retrieved Q App session.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>The Amazon Resource Name (ARN) of the new Q App session.</p>
    /// This field is required.
    pub fn session_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the new Q App session.</p>
    pub fn set_session_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the new Q App session.</p>
    pub fn get_session_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartQAppSessionOutput`](crate::operation::start_q_app_session::StartQAppSessionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`session_id`](crate::operation::start_q_app_session::builders::StartQAppSessionOutputBuilder::session_id)
    /// - [`session_arn`](crate::operation::start_q_app_session::builders::StartQAppSessionOutputBuilder::session_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_q_app_session::StartQAppSessionOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_q_app_session::StartQAppSessionOutput {
            session_id: self.session_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_id",
                    "session_id was not specified but it is required when building StartQAppSessionOutput",
                )
            })?,
            session_arn: self.session_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_arn",
                    "session_arn was not specified but it is required when building StartQAppSessionOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
