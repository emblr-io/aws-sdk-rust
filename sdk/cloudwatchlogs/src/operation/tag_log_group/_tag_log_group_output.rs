// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagLogGroupOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for TagLogGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl TagLogGroupOutput {
    /// Creates a new builder-style object to manufacture [`TagLogGroupOutput`](crate::operation::tag_log_group::TagLogGroupOutput).
    pub fn builder() -> crate::operation::tag_log_group::builders::TagLogGroupOutputBuilder {
        crate::operation::tag_log_group::builders::TagLogGroupOutputBuilder::default()
    }
}

/// A builder for [`TagLogGroupOutput`](crate::operation::tag_log_group::TagLogGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagLogGroupOutputBuilder {
    _request_id: Option<String>,
}
impl TagLogGroupOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`TagLogGroupOutput`](crate::operation::tag_log_group::TagLogGroupOutput).
    pub fn build(self) -> crate::operation::tag_log_group::TagLogGroupOutput {
        crate::operation::tag_log_group::TagLogGroupOutput {
            _request_id: self._request_id,
        }
    }
}
