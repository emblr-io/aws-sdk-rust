// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateLogStreamInput {
    /// <p>The name of the log group.</p>
    pub log_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the log stream.</p>
    pub log_stream_name: ::std::option::Option<::std::string::String>,
}
impl CreateLogStreamInput {
    /// <p>The name of the log group.</p>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
    /// <p>The name of the log stream.</p>
    pub fn log_stream_name(&self) -> ::std::option::Option<&str> {
        self.log_stream_name.as_deref()
    }
}
impl CreateLogStreamInput {
    /// Creates a new builder-style object to manufacture [`CreateLogStreamInput`](crate::operation::create_log_stream::CreateLogStreamInput).
    pub fn builder() -> crate::operation::create_log_stream::builders::CreateLogStreamInputBuilder {
        crate::operation::create_log_stream::builders::CreateLogStreamInputBuilder::default()
    }
}

/// A builder for [`CreateLogStreamInput`](crate::operation::create_log_stream::CreateLogStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateLogStreamInputBuilder {
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) log_stream_name: ::std::option::Option<::std::string::String>,
}
impl CreateLogStreamInputBuilder {
    /// <p>The name of the log group.</p>
    /// This field is required.
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log group.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The name of the log group.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>The name of the log stream.</p>
    /// This field is required.
    pub fn log_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log stream.</p>
    pub fn set_log_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_stream_name = input;
        self
    }
    /// <p>The name of the log stream.</p>
    pub fn get_log_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_stream_name
    }
    /// Consumes the builder and constructs a [`CreateLogStreamInput`](crate::operation::create_log_stream::CreateLogStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_log_stream::CreateLogStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_log_stream::CreateLogStreamInput {
            log_group_name: self.log_group_name,
            log_stream_name: self.log_stream_name,
        })
    }
}
