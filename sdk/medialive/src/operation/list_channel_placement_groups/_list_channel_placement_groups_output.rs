// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for ListChannelPlacementGroupsResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListChannelPlacementGroupsOutput {
    /// An array of ChannelPlacementGroups that exist in the Cluster.
    pub channel_placement_groups: ::std::option::Option<::std::vec::Vec<crate::types::DescribeChannelPlacementGroupSummary>>,
    /// Token for the next result.
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListChannelPlacementGroupsOutput {
    /// An array of ChannelPlacementGroups that exist in the Cluster.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.channel_placement_groups.is_none()`.
    pub fn channel_placement_groups(&self) -> &[crate::types::DescribeChannelPlacementGroupSummary] {
        self.channel_placement_groups.as_deref().unwrap_or_default()
    }
    /// Token for the next result.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListChannelPlacementGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListChannelPlacementGroupsOutput {
    /// Creates a new builder-style object to manufacture [`ListChannelPlacementGroupsOutput`](crate::operation::list_channel_placement_groups::ListChannelPlacementGroupsOutput).
    pub fn builder() -> crate::operation::list_channel_placement_groups::builders::ListChannelPlacementGroupsOutputBuilder {
        crate::operation::list_channel_placement_groups::builders::ListChannelPlacementGroupsOutputBuilder::default()
    }
}

/// A builder for [`ListChannelPlacementGroupsOutput`](crate::operation::list_channel_placement_groups::ListChannelPlacementGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListChannelPlacementGroupsOutputBuilder {
    pub(crate) channel_placement_groups: ::std::option::Option<::std::vec::Vec<crate::types::DescribeChannelPlacementGroupSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListChannelPlacementGroupsOutputBuilder {
    /// Appends an item to `channel_placement_groups`.
    ///
    /// To override the contents of this collection use [`set_channel_placement_groups`](Self::set_channel_placement_groups).
    ///
    /// An array of ChannelPlacementGroups that exist in the Cluster.
    pub fn channel_placement_groups(mut self, input: crate::types::DescribeChannelPlacementGroupSummary) -> Self {
        let mut v = self.channel_placement_groups.unwrap_or_default();
        v.push(input);
        self.channel_placement_groups = ::std::option::Option::Some(v);
        self
    }
    /// An array of ChannelPlacementGroups that exist in the Cluster.
    pub fn set_channel_placement_groups(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DescribeChannelPlacementGroupSummary>>,
    ) -> Self {
        self.channel_placement_groups = input;
        self
    }
    /// An array of ChannelPlacementGroups that exist in the Cluster.
    pub fn get_channel_placement_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DescribeChannelPlacementGroupSummary>> {
        &self.channel_placement_groups
    }
    /// Token for the next result.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// Token for the next result.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// Token for the next result.
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListChannelPlacementGroupsOutput`](crate::operation::list_channel_placement_groups::ListChannelPlacementGroupsOutput).
    pub fn build(self) -> crate::operation::list_channel_placement_groups::ListChannelPlacementGroupsOutput {
        crate::operation::list_channel_placement_groups::ListChannelPlacementGroupsOutput {
            channel_placement_groups: self.channel_placement_groups,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
