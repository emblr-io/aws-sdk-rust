// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveTagsFromResourceOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RemoveTagsFromResourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RemoveTagsFromResourceOutput {
    /// Creates a new builder-style object to manufacture [`RemoveTagsFromResourceOutput`](crate::operation::remove_tags_from_resource::RemoveTagsFromResourceOutput).
    pub fn builder() -> crate::operation::remove_tags_from_resource::builders::RemoveTagsFromResourceOutputBuilder {
        crate::operation::remove_tags_from_resource::builders::RemoveTagsFromResourceOutputBuilder::default()
    }
}

/// A builder for [`RemoveTagsFromResourceOutput`](crate::operation::remove_tags_from_resource::RemoveTagsFromResourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveTagsFromResourceOutputBuilder {
    _request_id: Option<String>,
}
impl RemoveTagsFromResourceOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RemoveTagsFromResourceOutput`](crate::operation::remove_tags_from_resource::RemoveTagsFromResourceOutput).
    pub fn build(self) -> crate::operation::remove_tags_from_resource::RemoveTagsFromResourceOutput {
        crate::operation::remove_tags_from_resource::RemoveTagsFromResourceOutput {
            _request_id: self._request_id,
        }
    }
}
