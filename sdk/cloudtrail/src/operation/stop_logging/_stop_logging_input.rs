// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Passes the request to CloudTrail to stop logging Amazon Web Services API calls for the specified account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopLoggingInput {
    /// <p>Specifies the name or the CloudTrail ARN of the trail for which CloudTrail will stop logging Amazon Web Services API calls. The following is the format of a trail ARN.</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl StopLoggingInput {
    /// <p>Specifies the name or the CloudTrail ARN of the trail for which CloudTrail will stop logging Amazon Web Services API calls. The following is the format of a trail ARN.</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl StopLoggingInput {
    /// Creates a new builder-style object to manufacture [`StopLoggingInput`](crate::operation::stop_logging::StopLoggingInput).
    pub fn builder() -> crate::operation::stop_logging::builders::StopLoggingInputBuilder {
        crate::operation::stop_logging::builders::StopLoggingInputBuilder::default()
    }
}

/// A builder for [`StopLoggingInput`](crate::operation::stop_logging::StopLoggingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopLoggingInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl StopLoggingInputBuilder {
    /// <p>Specifies the name or the CloudTrail ARN of the trail for which CloudTrail will stop logging Amazon Web Services API calls. The following is the format of a trail ARN.</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the name or the CloudTrail ARN of the trail for which CloudTrail will stop logging Amazon Web Services API calls. The following is the format of a trail ARN.</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Specifies the name or the CloudTrail ARN of the trail for which CloudTrail will stop logging Amazon Web Services API calls. The following is the format of a trail ARN.</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`StopLoggingInput`](crate::operation::stop_logging::StopLoggingInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::stop_logging::StopLoggingInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_logging::StopLoggingInput { name: self.name })
    }
}
