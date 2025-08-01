// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateActivityOutput {
    /// <p>The Amazon Resource Name (ARN) that identifies the created activity.</p>
    pub activity_arn: ::std::string::String,
    /// <p>The date the activity is created.</p>
    pub creation_date: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl CreateActivityOutput {
    /// <p>The Amazon Resource Name (ARN) that identifies the created activity.</p>
    pub fn activity_arn(&self) -> &str {
        use std::ops::Deref;
        self.activity_arn.deref()
    }
    /// <p>The date the activity is created.</p>
    pub fn creation_date(&self) -> &::aws_smithy_types::DateTime {
        &self.creation_date
    }
}
impl ::aws_types::request_id::RequestId for CreateActivityOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateActivityOutput {
    /// Creates a new builder-style object to manufacture [`CreateActivityOutput`](crate::operation::create_activity::CreateActivityOutput).
    pub fn builder() -> crate::operation::create_activity::builders::CreateActivityOutputBuilder {
        crate::operation::create_activity::builders::CreateActivityOutputBuilder::default()
    }
}

/// A builder for [`CreateActivityOutput`](crate::operation::create_activity::CreateActivityOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateActivityOutputBuilder {
    pub(crate) activity_arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CreateActivityOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) that identifies the created activity.</p>
    /// This field is required.
    pub fn activity_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.activity_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the created activity.</p>
    pub fn set_activity_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.activity_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the created activity.</p>
    pub fn get_activity_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.activity_arn
    }
    /// <p>The date the activity is created.</p>
    /// This field is required.
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date the activity is created.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date the activity is created.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateActivityOutput`](crate::operation::create_activity::CreateActivityOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`activity_arn`](crate::operation::create_activity::builders::CreateActivityOutputBuilder::activity_arn)
    /// - [`creation_date`](crate::operation::create_activity::builders::CreateActivityOutputBuilder::creation_date)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_activity::CreateActivityOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_activity::CreateActivityOutput {
            activity_arn: self.activity_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "activity_arn",
                    "activity_arn was not specified but it is required when building CreateActivityOutput",
                )
            })?,
            creation_date: self.creation_date.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_date",
                    "creation_date was not specified but it is required when building CreateActivityOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
