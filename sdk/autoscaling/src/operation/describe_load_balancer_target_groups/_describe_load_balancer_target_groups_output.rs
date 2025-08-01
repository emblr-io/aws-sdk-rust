// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLoadBalancerTargetGroupsOutput {
    /// <p>Information about the target groups.</p>
    pub load_balancer_target_groups: ::std::option::Option<::std::vec::Vec<crate::types::LoadBalancerTargetGroupState>>,
    /// <p>A string that indicates that the response contains more items than can be returned in a single response. To receive additional items, specify this string for the <code>NextToken</code> value when requesting the next set of items. This value is null when there are no more items to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeLoadBalancerTargetGroupsOutput {
    /// <p>Information about the target groups.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.load_balancer_target_groups.is_none()`.
    pub fn load_balancer_target_groups(&self) -> &[crate::types::LoadBalancerTargetGroupState] {
        self.load_balancer_target_groups.as_deref().unwrap_or_default()
    }
    /// <p>A string that indicates that the response contains more items than can be returned in a single response. To receive additional items, specify this string for the <code>NextToken</code> value when requesting the next set of items. This value is null when there are no more items to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeLoadBalancerTargetGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeLoadBalancerTargetGroupsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeLoadBalancerTargetGroupsOutput`](crate::operation::describe_load_balancer_target_groups::DescribeLoadBalancerTargetGroupsOutput).
    pub fn builder() -> crate::operation::describe_load_balancer_target_groups::builders::DescribeLoadBalancerTargetGroupsOutputBuilder {
        crate::operation::describe_load_balancer_target_groups::builders::DescribeLoadBalancerTargetGroupsOutputBuilder::default()
    }
}

/// A builder for [`DescribeLoadBalancerTargetGroupsOutput`](crate::operation::describe_load_balancer_target_groups::DescribeLoadBalancerTargetGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLoadBalancerTargetGroupsOutputBuilder {
    pub(crate) load_balancer_target_groups: ::std::option::Option<::std::vec::Vec<crate::types::LoadBalancerTargetGroupState>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeLoadBalancerTargetGroupsOutputBuilder {
    /// Appends an item to `load_balancer_target_groups`.
    ///
    /// To override the contents of this collection use [`set_load_balancer_target_groups`](Self::set_load_balancer_target_groups).
    ///
    /// <p>Information about the target groups.</p>
    pub fn load_balancer_target_groups(mut self, input: crate::types::LoadBalancerTargetGroupState) -> Self {
        let mut v = self.load_balancer_target_groups.unwrap_or_default();
        v.push(input);
        self.load_balancer_target_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the target groups.</p>
    pub fn set_load_balancer_target_groups(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::LoadBalancerTargetGroupState>>,
    ) -> Self {
        self.load_balancer_target_groups = input;
        self
    }
    /// <p>Information about the target groups.</p>
    pub fn get_load_balancer_target_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LoadBalancerTargetGroupState>> {
        &self.load_balancer_target_groups
    }
    /// <p>A string that indicates that the response contains more items than can be returned in a single response. To receive additional items, specify this string for the <code>NextToken</code> value when requesting the next set of items. This value is null when there are no more items to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that indicates that the response contains more items than can be returned in a single response. To receive additional items, specify this string for the <code>NextToken</code> value when requesting the next set of items. This value is null when there are no more items to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A string that indicates that the response contains more items than can be returned in a single response. To receive additional items, specify this string for the <code>NextToken</code> value when requesting the next set of items. This value is null when there are no more items to return.</p>
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
    /// Consumes the builder and constructs a [`DescribeLoadBalancerTargetGroupsOutput`](crate::operation::describe_load_balancer_target_groups::DescribeLoadBalancerTargetGroupsOutput).
    pub fn build(self) -> crate::operation::describe_load_balancer_target_groups::DescribeLoadBalancerTargetGroupsOutput {
        crate::operation::describe_load_balancer_target_groups::DescribeLoadBalancerTargetGroupsOutput {
            load_balancer_target_groups: self.load_balancer_target_groups,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
