// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input for <code>DeleteStream</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteStreamInput {
    /// <p>The name of the stream to delete.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>If this parameter is unset (<code>null</code>) or if you set it to <code>false</code>, and the stream has registered consumers, the call to <code>DeleteStream</code> fails with a <code>ResourceInUseException</code>.</p>
    pub enforce_consumer_deletion: ::std::option::Option<bool>,
    /// <p>The ARN of the stream.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteStreamInput {
    /// <p>The name of the stream to delete.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>If this parameter is unset (<code>null</code>) or if you set it to <code>false</code>, and the stream has registered consumers, the call to <code>DeleteStream</code> fails with a <code>ResourceInUseException</code>.</p>
    pub fn enforce_consumer_deletion(&self) -> ::std::option::Option<bool> {
        self.enforce_consumer_deletion
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
}
impl DeleteStreamInput {
    /// Creates a new builder-style object to manufacture [`DeleteStreamInput`](crate::operation::delete_stream::DeleteStreamInput).
    pub fn builder() -> crate::operation::delete_stream::builders::DeleteStreamInputBuilder {
        crate::operation::delete_stream::builders::DeleteStreamInputBuilder::default()
    }
}

/// A builder for [`DeleteStreamInput`](crate::operation::delete_stream::DeleteStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteStreamInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) enforce_consumer_deletion: ::std::option::Option<bool>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteStreamInputBuilder {
    /// <p>The name of the stream to delete.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stream to delete.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the stream to delete.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>If this parameter is unset (<code>null</code>) or if you set it to <code>false</code>, and the stream has registered consumers, the call to <code>DeleteStream</code> fails with a <code>ResourceInUseException</code>.</p>
    pub fn enforce_consumer_deletion(mut self, input: bool) -> Self {
        self.enforce_consumer_deletion = ::std::option::Option::Some(input);
        self
    }
    /// <p>If this parameter is unset (<code>null</code>) or if you set it to <code>false</code>, and the stream has registered consumers, the call to <code>DeleteStream</code> fails with a <code>ResourceInUseException</code>.</p>
    pub fn set_enforce_consumer_deletion(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enforce_consumer_deletion = input;
        self
    }
    /// <p>If this parameter is unset (<code>null</code>) or if you set it to <code>false</code>, and the stream has registered consumers, the call to <code>DeleteStream</code> fails with a <code>ResourceInUseException</code>.</p>
    pub fn get_enforce_consumer_deletion(&self) -> &::std::option::Option<bool> {
        &self.enforce_consumer_deletion
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// Consumes the builder and constructs a [`DeleteStreamInput`](crate::operation::delete_stream::DeleteStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_stream::DeleteStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_stream::DeleteStreamInput {
            stream_name: self.stream_name,
            enforce_consumer_deletion: self.enforce_consumer_deletion,
            stream_arn: self.stream_arn,
        })
    }
}
