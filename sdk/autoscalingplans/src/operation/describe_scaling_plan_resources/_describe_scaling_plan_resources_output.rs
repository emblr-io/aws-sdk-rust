// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeScalingPlanResourcesOutput {
    /// <p>Information about the scalable resources.</p>
    pub scaling_plan_resources: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPlanResource>>,
    /// <p>The token required to get the next set of results. This value is <code>null</code> if there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeScalingPlanResourcesOutput {
    /// <p>Information about the scalable resources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.scaling_plan_resources.is_none()`.
    pub fn scaling_plan_resources(&self) -> &[crate::types::ScalingPlanResource] {
        self.scaling_plan_resources.as_deref().unwrap_or_default()
    }
    /// <p>The token required to get the next set of results. This value is <code>null</code> if there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeScalingPlanResourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeScalingPlanResourcesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeScalingPlanResourcesOutput`](crate::operation::describe_scaling_plan_resources::DescribeScalingPlanResourcesOutput).
    pub fn builder() -> crate::operation::describe_scaling_plan_resources::builders::DescribeScalingPlanResourcesOutputBuilder {
        crate::operation::describe_scaling_plan_resources::builders::DescribeScalingPlanResourcesOutputBuilder::default()
    }
}

/// A builder for [`DescribeScalingPlanResourcesOutput`](crate::operation::describe_scaling_plan_resources::DescribeScalingPlanResourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeScalingPlanResourcesOutputBuilder {
    pub(crate) scaling_plan_resources: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPlanResource>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeScalingPlanResourcesOutputBuilder {
    /// Appends an item to `scaling_plan_resources`.
    ///
    /// To override the contents of this collection use [`set_scaling_plan_resources`](Self::set_scaling_plan_resources).
    ///
    /// <p>Information about the scalable resources.</p>
    pub fn scaling_plan_resources(mut self, input: crate::types::ScalingPlanResource) -> Self {
        let mut v = self.scaling_plan_resources.unwrap_or_default();
        v.push(input);
        self.scaling_plan_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the scalable resources.</p>
    pub fn set_scaling_plan_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ScalingPlanResource>>) -> Self {
        self.scaling_plan_resources = input;
        self
    }
    /// <p>Information about the scalable resources.</p>
    pub fn get_scaling_plan_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ScalingPlanResource>> {
        &self.scaling_plan_resources
    }
    /// <p>The token required to get the next set of results. This value is <code>null</code> if there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token required to get the next set of results. This value is <code>null</code> if there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token required to get the next set of results. This value is <code>null</code> if there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`DescribeScalingPlanResourcesOutput`](crate::operation::describe_scaling_plan_resources::DescribeScalingPlanResourcesOutput).
    pub fn build(self) -> crate::operation::describe_scaling_plan_resources::DescribeScalingPlanResourcesOutput {
        crate::operation::describe_scaling_plan_resources::DescribeScalingPlanResourcesOutput {
            scaling_plan_resources: self.scaling_plan_resources,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
