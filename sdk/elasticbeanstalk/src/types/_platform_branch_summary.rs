// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about a platform branch.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PlatformBranchSummary {
    /// <p>The name of the platform to which this platform branch belongs.</p>
    pub platform_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the platform branch.</p>
    pub branch_name: ::std::option::Option<::std::string::String>,
    /// <p>The support life cycle state of the platform branch.</p>
    /// <p>Possible values: <code>beta</code> | <code>supported</code> | <code>deprecated</code> | <code>retired</code></p>
    pub lifecycle_state: ::std::option::Option<::std::string::String>,
    /// <p>An ordinal number that designates the order in which platform branches have been added to a platform. This can be helpful, for example, if your code calls the <code>ListPlatformBranches</code> action and then displays a list of platform branches.</p>
    /// <p>A larger <code>BranchOrder</code> value designates a newer platform branch within the platform.</p>
    pub branch_order: i32,
    /// <p>The environment tiers that platform versions in this branch support.</p>
    /// <p>Possible values: <code>WebServer/Standard</code> | <code>Worker/SQS/HTTP</code></p>
    pub supported_tier_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl PlatformBranchSummary {
    /// <p>The name of the platform to which this platform branch belongs.</p>
    pub fn platform_name(&self) -> ::std::option::Option<&str> {
        self.platform_name.as_deref()
    }
    /// <p>The name of the platform branch.</p>
    pub fn branch_name(&self) -> ::std::option::Option<&str> {
        self.branch_name.as_deref()
    }
    /// <p>The support life cycle state of the platform branch.</p>
    /// <p>Possible values: <code>beta</code> | <code>supported</code> | <code>deprecated</code> | <code>retired</code></p>
    pub fn lifecycle_state(&self) -> ::std::option::Option<&str> {
        self.lifecycle_state.as_deref()
    }
    /// <p>An ordinal number that designates the order in which platform branches have been added to a platform. This can be helpful, for example, if your code calls the <code>ListPlatformBranches</code> action and then displays a list of platform branches.</p>
    /// <p>A larger <code>BranchOrder</code> value designates a newer platform branch within the platform.</p>
    pub fn branch_order(&self) -> i32 {
        self.branch_order
    }
    /// <p>The environment tiers that platform versions in this branch support.</p>
    /// <p>Possible values: <code>WebServer/Standard</code> | <code>Worker/SQS/HTTP</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_tier_list.is_none()`.
    pub fn supported_tier_list(&self) -> &[::std::string::String] {
        self.supported_tier_list.as_deref().unwrap_or_default()
    }
}
impl PlatformBranchSummary {
    /// Creates a new builder-style object to manufacture [`PlatformBranchSummary`](crate::types::PlatformBranchSummary).
    pub fn builder() -> crate::types::builders::PlatformBranchSummaryBuilder {
        crate::types::builders::PlatformBranchSummaryBuilder::default()
    }
}

/// A builder for [`PlatformBranchSummary`](crate::types::PlatformBranchSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PlatformBranchSummaryBuilder {
    pub(crate) platform_name: ::std::option::Option<::std::string::String>,
    pub(crate) branch_name: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_state: ::std::option::Option<::std::string::String>,
    pub(crate) branch_order: ::std::option::Option<i32>,
    pub(crate) supported_tier_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl PlatformBranchSummaryBuilder {
    /// <p>The name of the platform to which this platform branch belongs.</p>
    pub fn platform_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the platform to which this platform branch belongs.</p>
    pub fn set_platform_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform_name = input;
        self
    }
    /// <p>The name of the platform to which this platform branch belongs.</p>
    pub fn get_platform_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform_name
    }
    /// <p>The name of the platform branch.</p>
    pub fn branch_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.branch_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the platform branch.</p>
    pub fn set_branch_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.branch_name = input;
        self
    }
    /// <p>The name of the platform branch.</p>
    pub fn get_branch_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.branch_name
    }
    /// <p>The support life cycle state of the platform branch.</p>
    /// <p>Possible values: <code>beta</code> | <code>supported</code> | <code>deprecated</code> | <code>retired</code></p>
    pub fn lifecycle_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The support life cycle state of the platform branch.</p>
    /// <p>Possible values: <code>beta</code> | <code>supported</code> | <code>deprecated</code> | <code>retired</code></p>
    pub fn set_lifecycle_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_state = input;
        self
    }
    /// <p>The support life cycle state of the platform branch.</p>
    /// <p>Possible values: <code>beta</code> | <code>supported</code> | <code>deprecated</code> | <code>retired</code></p>
    pub fn get_lifecycle_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_state
    }
    /// <p>An ordinal number that designates the order in which platform branches have been added to a platform. This can be helpful, for example, if your code calls the <code>ListPlatformBranches</code> action and then displays a list of platform branches.</p>
    /// <p>A larger <code>BranchOrder</code> value designates a newer platform branch within the platform.</p>
    pub fn branch_order(mut self, input: i32) -> Self {
        self.branch_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>An ordinal number that designates the order in which platform branches have been added to a platform. This can be helpful, for example, if your code calls the <code>ListPlatformBranches</code> action and then displays a list of platform branches.</p>
    /// <p>A larger <code>BranchOrder</code> value designates a newer platform branch within the platform.</p>
    pub fn set_branch_order(mut self, input: ::std::option::Option<i32>) -> Self {
        self.branch_order = input;
        self
    }
    /// <p>An ordinal number that designates the order in which platform branches have been added to a platform. This can be helpful, for example, if your code calls the <code>ListPlatformBranches</code> action and then displays a list of platform branches.</p>
    /// <p>A larger <code>BranchOrder</code> value designates a newer platform branch within the platform.</p>
    pub fn get_branch_order(&self) -> &::std::option::Option<i32> {
        &self.branch_order
    }
    /// Appends an item to `supported_tier_list`.
    ///
    /// To override the contents of this collection use [`set_supported_tier_list`](Self::set_supported_tier_list).
    ///
    /// <p>The environment tiers that platform versions in this branch support.</p>
    /// <p>Possible values: <code>WebServer/Standard</code> | <code>Worker/SQS/HTTP</code></p>
    pub fn supported_tier_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.supported_tier_list.unwrap_or_default();
        v.push(input.into());
        self.supported_tier_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The environment tiers that platform versions in this branch support.</p>
    /// <p>Possible values: <code>WebServer/Standard</code> | <code>Worker/SQS/HTTP</code></p>
    pub fn set_supported_tier_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.supported_tier_list = input;
        self
    }
    /// <p>The environment tiers that platform versions in this branch support.</p>
    /// <p>Possible values: <code>WebServer/Standard</code> | <code>Worker/SQS/HTTP</code></p>
    pub fn get_supported_tier_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.supported_tier_list
    }
    /// Consumes the builder and constructs a [`PlatformBranchSummary`](crate::types::PlatformBranchSummary).
    pub fn build(self) -> crate::types::PlatformBranchSummary {
        crate::types::PlatformBranchSummary {
            platform_name: self.platform_name,
            branch_name: self.branch_name,
            lifecycle_state: self.lifecycle_state,
            branch_order: self.branch_order.unwrap_or_default(),
            supported_tier_list: self.supported_tier_list,
        }
    }
}
