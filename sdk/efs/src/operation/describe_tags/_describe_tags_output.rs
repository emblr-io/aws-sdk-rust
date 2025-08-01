// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTagsOutput {
    /// <p>If the request included a <code>Marker</code>, the response returns that value in this field.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>Returns tags associated with the file system as an array of <code>Tag</code> objects.</p>
    pub tags: ::std::vec::Vec<crate::types::Tag>,
    /// <p>If a value is present, there are more tags to return. In a subsequent request, you can provide the value of <code>NextMarker</code> as the value of the <code>Marker</code> parameter in your next request to retrieve the next set of tags.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeTagsOutput {
    /// <p>If the request included a <code>Marker</code>, the response returns that value in this field.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>Returns tags associated with the file system as an array of <code>Tag</code> objects.</p>
    pub fn tags(&self) -> &[crate::types::Tag] {
        use std::ops::Deref;
        self.tags.deref()
    }
    /// <p>If a value is present, there are more tags to return. In a subsequent request, you can provide the value of <code>NextMarker</code> as the value of the <code>Marker</code> parameter in your next request to retrieve the next set of tags.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeTagsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeTagsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeTagsOutput`](crate::operation::describe_tags::DescribeTagsOutput).
    pub fn builder() -> crate::operation::describe_tags::builders::DescribeTagsOutputBuilder {
        crate::operation::describe_tags::builders::DescribeTagsOutputBuilder::default()
    }
}

/// A builder for [`DescribeTagsOutput`](crate::operation::describe_tags::DescribeTagsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTagsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeTagsOutputBuilder {
    /// <p>If the request included a <code>Marker</code>, the response returns that value in this field.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the request included a <code>Marker</code>, the response returns that value in this field.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>If the request included a <code>Marker</code>, the response returns that value in this field.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Returns tags associated with the file system as an array of <code>Tag</code> objects.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Returns tags associated with the file system as an array of <code>Tag</code> objects.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Returns tags associated with the file system as an array of <code>Tag</code> objects.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>If a value is present, there are more tags to return. In a subsequent request, you can provide the value of <code>NextMarker</code> as the value of the <code>Marker</code> parameter in your next request to retrieve the next set of tags.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If a value is present, there are more tags to return. In a subsequent request, you can provide the value of <code>NextMarker</code> as the value of the <code>Marker</code> parameter in your next request to retrieve the next set of tags.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>If a value is present, there are more tags to return. In a subsequent request, you can provide the value of <code>NextMarker</code> as the value of the <code>Marker</code> parameter in your next request to retrieve the next set of tags.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeTagsOutput`](crate::operation::describe_tags::DescribeTagsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`tags`](crate::operation::describe_tags::builders::DescribeTagsOutputBuilder::tags)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_tags::DescribeTagsOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_tags::DescribeTagsOutput {
            marker: self.marker,
            tags: self.tags.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tags",
                    "tags was not specified but it is required when building DescribeTagsOutput",
                )
            })?,
            next_marker: self.next_marker,
            _request_id: self._request_id,
        })
    }
}
