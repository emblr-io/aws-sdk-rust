// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagStreamOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for TagStreamOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl TagStreamOutput {
    /// Creates a new builder-style object to manufacture [`TagStreamOutput`](crate::operation::tag_stream::TagStreamOutput).
    pub fn builder() -> crate::operation::tag_stream::builders::TagStreamOutputBuilder {
        crate::operation::tag_stream::builders::TagStreamOutputBuilder::default()
    }
}

/// A builder for [`TagStreamOutput`](crate::operation::tag_stream::TagStreamOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagStreamOutputBuilder {
    _request_id: Option<String>,
}
impl TagStreamOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`TagStreamOutput`](crate::operation::tag_stream::TagStreamOutput).
    pub fn build(self) -> crate::operation::tag_stream::TagStreamOutput {
        crate::operation::tag_stream::TagStreamOutput {
            _request_id: self._request_id,
        }
    }
}
