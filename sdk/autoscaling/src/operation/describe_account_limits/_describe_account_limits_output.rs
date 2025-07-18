// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAccountLimitsOutput {
    /// <p>The maximum number of groups allowed for your account. The default is 200 groups per Region.</p>
    pub max_number_of_auto_scaling_groups: ::std::option::Option<i32>,
    /// <p>The maximum number of launch configurations allowed for your account. The default is 200 launch configurations per Region.</p>
    pub max_number_of_launch_configurations: ::std::option::Option<i32>,
    /// <p>The current number of groups for your account.</p>
    pub number_of_auto_scaling_groups: ::std::option::Option<i32>,
    /// <p>The current number of launch configurations for your account.</p>
    pub number_of_launch_configurations: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl DescribeAccountLimitsOutput {
    /// <p>The maximum number of groups allowed for your account. The default is 200 groups per Region.</p>
    pub fn max_number_of_auto_scaling_groups(&self) -> ::std::option::Option<i32> {
        self.max_number_of_auto_scaling_groups
    }
    /// <p>The maximum number of launch configurations allowed for your account. The default is 200 launch configurations per Region.</p>
    pub fn max_number_of_launch_configurations(&self) -> ::std::option::Option<i32> {
        self.max_number_of_launch_configurations
    }
    /// <p>The current number of groups for your account.</p>
    pub fn number_of_auto_scaling_groups(&self) -> ::std::option::Option<i32> {
        self.number_of_auto_scaling_groups
    }
    /// <p>The current number of launch configurations for your account.</p>
    pub fn number_of_launch_configurations(&self) -> ::std::option::Option<i32> {
        self.number_of_launch_configurations
    }
}
impl ::aws_types::request_id::RequestId for DescribeAccountLimitsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeAccountLimitsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeAccountLimitsOutput`](crate::operation::describe_account_limits::DescribeAccountLimitsOutput).
    pub fn builder() -> crate::operation::describe_account_limits::builders::DescribeAccountLimitsOutputBuilder {
        crate::operation::describe_account_limits::builders::DescribeAccountLimitsOutputBuilder::default()
    }
}

/// A builder for [`DescribeAccountLimitsOutput`](crate::operation::describe_account_limits::DescribeAccountLimitsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAccountLimitsOutputBuilder {
    pub(crate) max_number_of_auto_scaling_groups: ::std::option::Option<i32>,
    pub(crate) max_number_of_launch_configurations: ::std::option::Option<i32>,
    pub(crate) number_of_auto_scaling_groups: ::std::option::Option<i32>,
    pub(crate) number_of_launch_configurations: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl DescribeAccountLimitsOutputBuilder {
    /// <p>The maximum number of groups allowed for your account. The default is 200 groups per Region.</p>
    pub fn max_number_of_auto_scaling_groups(mut self, input: i32) -> Self {
        self.max_number_of_auto_scaling_groups = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of groups allowed for your account. The default is 200 groups per Region.</p>
    pub fn set_max_number_of_auto_scaling_groups(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_number_of_auto_scaling_groups = input;
        self
    }
    /// <p>The maximum number of groups allowed for your account. The default is 200 groups per Region.</p>
    pub fn get_max_number_of_auto_scaling_groups(&self) -> &::std::option::Option<i32> {
        &self.max_number_of_auto_scaling_groups
    }
    /// <p>The maximum number of launch configurations allowed for your account. The default is 200 launch configurations per Region.</p>
    pub fn max_number_of_launch_configurations(mut self, input: i32) -> Self {
        self.max_number_of_launch_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of launch configurations allowed for your account. The default is 200 launch configurations per Region.</p>
    pub fn set_max_number_of_launch_configurations(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_number_of_launch_configurations = input;
        self
    }
    /// <p>The maximum number of launch configurations allowed for your account. The default is 200 launch configurations per Region.</p>
    pub fn get_max_number_of_launch_configurations(&self) -> &::std::option::Option<i32> {
        &self.max_number_of_launch_configurations
    }
    /// <p>The current number of groups for your account.</p>
    pub fn number_of_auto_scaling_groups(mut self, input: i32) -> Self {
        self.number_of_auto_scaling_groups = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current number of groups for your account.</p>
    pub fn set_number_of_auto_scaling_groups(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_auto_scaling_groups = input;
        self
    }
    /// <p>The current number of groups for your account.</p>
    pub fn get_number_of_auto_scaling_groups(&self) -> &::std::option::Option<i32> {
        &self.number_of_auto_scaling_groups
    }
    /// <p>The current number of launch configurations for your account.</p>
    pub fn number_of_launch_configurations(mut self, input: i32) -> Self {
        self.number_of_launch_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current number of launch configurations for your account.</p>
    pub fn set_number_of_launch_configurations(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_launch_configurations = input;
        self
    }
    /// <p>The current number of launch configurations for your account.</p>
    pub fn get_number_of_launch_configurations(&self) -> &::std::option::Option<i32> {
        &self.number_of_launch_configurations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeAccountLimitsOutput`](crate::operation::describe_account_limits::DescribeAccountLimitsOutput).
    pub fn build(self) -> crate::operation::describe_account_limits::DescribeAccountLimitsOutput {
        crate::operation::describe_account_limits::DescribeAccountLimitsOutput {
            max_number_of_auto_scaling_groups: self.max_number_of_auto_scaling_groups,
            max_number_of_launch_configurations: self.max_number_of_launch_configurations,
            number_of_auto_scaling_groups: self.number_of_auto_scaling_groups,
            number_of_launch_configurations: self.number_of_launch_configurations,
            _request_id: self._request_id,
        }
    }
}
