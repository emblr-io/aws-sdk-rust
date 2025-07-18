// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeGroupsOutput {
    /// <p>The list of groups.</p>
    pub groups: ::std::option::Option<::std::vec::Vec<crate::types::GroupMetadata>>,
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeGroupsOutput {
    /// <p>The list of groups.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.groups.is_none()`.
    pub fn groups(&self) -> &[crate::types::GroupMetadata] {
        self.groups.as_deref().unwrap_or_default()
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeGroupsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeGroupsOutput`](crate::operation::describe_groups::DescribeGroupsOutput).
    pub fn builder() -> crate::operation::describe_groups::builders::DescribeGroupsOutputBuilder {
        crate::operation::describe_groups::builders::DescribeGroupsOutputBuilder::default()
    }
}

/// A builder for [`DescribeGroupsOutput`](crate::operation::describe_groups::DescribeGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeGroupsOutputBuilder {
    pub(crate) groups: ::std::option::Option<::std::vec::Vec<crate::types::GroupMetadata>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeGroupsOutputBuilder {
    /// Appends an item to `groups`.
    ///
    /// To override the contents of this collection use [`set_groups`](Self::set_groups).
    ///
    /// <p>The list of groups.</p>
    pub fn groups(mut self, input: crate::types::GroupMetadata) -> Self {
        let mut v = self.groups.unwrap_or_default();
        v.push(input);
        self.groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of groups.</p>
    pub fn set_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GroupMetadata>>) -> Self {
        self.groups = input;
        self
    }
    /// <p>The list of groups.</p>
    pub fn get_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GroupMetadata>> {
        &self.groups
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The marker to use when requesting the next set of results. If there are no additional results, the string is empty.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeGroupsOutput`](crate::operation::describe_groups::DescribeGroupsOutput).
    pub fn build(self) -> crate::operation::describe_groups::DescribeGroupsOutput {
        crate::operation::describe_groups::DescribeGroupsOutput {
            groups: self.groups,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
