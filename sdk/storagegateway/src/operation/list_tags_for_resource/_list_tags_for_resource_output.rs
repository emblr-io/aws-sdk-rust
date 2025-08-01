// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>ListTagsForResourceOutput</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTagsForResourceOutput {
    /// <p>The Amazon Resource Name (ARN) of the resource for which you want to list tags.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>An opaque string that indicates the position at which to stop returning the list of tags.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>An array that contains the tags for the specified resource.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    _request_id: Option<String>,
}
impl ListTagsForResourceOutput {
    /// <p>The Amazon Resource Name (ARN) of the resource for which you want to list tags.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>An opaque string that indicates the position at which to stop returning the list of tags.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>An array that contains the tags for the specified resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListTagsForResourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListTagsForResourceOutput {
    /// Creates a new builder-style object to manufacture [`ListTagsForResourceOutput`](crate::operation::list_tags_for_resource::ListTagsForResourceOutput).
    pub fn builder() -> crate::operation::list_tags_for_resource::builders::ListTagsForResourceOutputBuilder {
        crate::operation::list_tags_for_resource::builders::ListTagsForResourceOutputBuilder::default()
    }
}

/// A builder for [`ListTagsForResourceOutput`](crate::operation::list_tags_for_resource::ListTagsForResourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTagsForResourceOutputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    _request_id: Option<String>,
}
impl ListTagsForResourceOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the resource for which you want to list tags.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource for which you want to list tags.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource for which you want to list tags.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>An opaque string that indicates the position at which to stop returning the list of tags.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An opaque string that indicates the position at which to stop returning the list of tags.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An opaque string that indicates the position at which to stop returning the list of tags.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array that contains the tags for the specified resource.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that contains the tags for the specified resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array that contains the tags for the specified resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListTagsForResourceOutput`](crate::operation::list_tags_for_resource::ListTagsForResourceOutput).
    pub fn build(self) -> crate::operation::list_tags_for_resource::ListTagsForResourceOutput {
        crate::operation::list_tags_for_resource::ListTagsForResourceOutput {
            resource_arn: self.resource_arn,
            marker: self.marker,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
