// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A chunk of the streamed response payload.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct InvokeResponseStreamUpdate {
    /// <p>Data returned by your Lambda function.</p>
    pub payload: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl InvokeResponseStreamUpdate {
    /// <p>Data returned by your Lambda function.</p>
    pub fn payload(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.payload.as_ref()
    }
}
impl ::std::fmt::Debug for InvokeResponseStreamUpdate {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeResponseStreamUpdate");
        formatter.field("payload", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl InvokeResponseStreamUpdate {
    /// Creates a new builder-style object to manufacture [`InvokeResponseStreamUpdate`](crate::types::InvokeResponseStreamUpdate).
    pub fn builder() -> crate::types::builders::InvokeResponseStreamUpdateBuilder {
        crate::types::builders::InvokeResponseStreamUpdateBuilder::default()
    }
}

/// A builder for [`InvokeResponseStreamUpdate`](crate::types::InvokeResponseStreamUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct InvokeResponseStreamUpdateBuilder {
    pub(crate) payload: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl InvokeResponseStreamUpdateBuilder {
    /// <p>Data returned by your Lambda function.</p>
    pub fn payload(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>Data returned by your Lambda function.</p>
    pub fn set_payload(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.payload = input;
        self
    }
    /// <p>Data returned by your Lambda function.</p>
    pub fn get_payload(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.payload
    }
    /// Consumes the builder and constructs a [`InvokeResponseStreamUpdate`](crate::types::InvokeResponseStreamUpdate).
    pub fn build(self) -> crate::types::InvokeResponseStreamUpdate {
        crate::types::InvokeResponseStreamUpdate { payload: self.payload }
    }
}
impl ::std::fmt::Debug for InvokeResponseStreamUpdateBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeResponseStreamUpdateBuilder");
        formatter.field("payload", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
