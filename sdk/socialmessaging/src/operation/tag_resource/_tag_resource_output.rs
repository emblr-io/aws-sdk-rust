// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagResourceOutput {
    /// <p>The status code of the tag resource operation.</p>
    pub status_code: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl TagResourceOutput {
    /// <p>The status code of the tag resource operation.</p>
    pub fn status_code(&self) -> ::std::option::Option<i32> {
        self.status_code
    }
}
impl ::aws_types::request_id::RequestId for TagResourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl TagResourceOutput {
    /// Creates a new builder-style object to manufacture [`TagResourceOutput`](crate::operation::tag_resource::TagResourceOutput).
    pub fn builder() -> crate::operation::tag_resource::builders::TagResourceOutputBuilder {
        crate::operation::tag_resource::builders::TagResourceOutputBuilder::default()
    }
}

/// A builder for [`TagResourceOutput`](crate::operation::tag_resource::TagResourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagResourceOutputBuilder {
    pub(crate) status_code: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl TagResourceOutputBuilder {
    /// <p>The status code of the tag resource operation.</p>
    pub fn status_code(mut self, input: i32) -> Self {
        self.status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status code of the tag resource operation.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The status code of the tag resource operation.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<i32> {
        &self.status_code
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`TagResourceOutput`](crate::operation::tag_resource::TagResourceOutput).
    pub fn build(self) -> crate::operation::tag_resource::TagResourceOutput {
        crate::operation::tag_resource::TagResourceOutput {
            status_code: self.status_code,
            _request_id: self._request_id,
        }
    }
}
