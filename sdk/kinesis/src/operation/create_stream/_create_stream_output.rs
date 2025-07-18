// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateStreamOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for CreateStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateStreamOutput {
    /// Creates a new builder-style object to manufacture [`CreateStreamOutput`](crate::operation::create_stream::CreateStreamOutput).
    pub fn builder() -> crate::operation::create_stream::builders::CreateStreamOutputBuilder {
        crate::operation::create_stream::builders::CreateStreamOutputBuilder::default()
    }
}

/// A builder for [`CreateStreamOutput`](crate::operation::create_stream::CreateStreamOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateStreamOutputBuilder {
    _request_id: Option<String>,
}
impl CreateStreamOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateStreamOutput`](crate::operation::create_stream::CreateStreamOutput).
    pub fn build(self) -> crate::operation::create_stream::CreateStreamOutput {
        crate::operation::create_stream::CreateStreamOutput {
            _request_id: self._request_id,
        }
    }
}
