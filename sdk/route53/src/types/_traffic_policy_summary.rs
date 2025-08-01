// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains information about the latest version of one traffic policy that is associated with the current Amazon Web Services account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TrafficPolicySummary {
    /// <p>The ID that Amazon Route 53 assigned to the traffic policy when you created it.</p>
    pub id: ::std::string::String,
    /// <p>The name that you specified for the traffic policy when you created it.</p>
    pub name: ::std::string::String,
    /// <p>The DNS type of the resource record sets that Amazon Route 53 creates when you use a traffic policy to create a traffic policy instance.</p>
    pub r#type: crate::types::RrType,
    /// <p>The version number of the latest version of the traffic policy.</p>
    pub latest_version: i32,
    /// <p>The number of traffic policies that are associated with the current Amazon Web Services account.</p>
    pub traffic_policy_count: i32,
}
impl TrafficPolicySummary {
    /// <p>The ID that Amazon Route 53 assigned to the traffic policy when you created it.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name that you specified for the traffic policy when you created it.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The DNS type of the resource record sets that Amazon Route 53 creates when you use a traffic policy to create a traffic policy instance.</p>
    pub fn r#type(&self) -> &crate::types::RrType {
        &self.r#type
    }
    /// <p>The version number of the latest version of the traffic policy.</p>
    pub fn latest_version(&self) -> i32 {
        self.latest_version
    }
    /// <p>The number of traffic policies that are associated with the current Amazon Web Services account.</p>
    pub fn traffic_policy_count(&self) -> i32 {
        self.traffic_policy_count
    }
}
impl TrafficPolicySummary {
    /// Creates a new builder-style object to manufacture [`TrafficPolicySummary`](crate::types::TrafficPolicySummary).
    pub fn builder() -> crate::types::builders::TrafficPolicySummaryBuilder {
        crate::types::builders::TrafficPolicySummaryBuilder::default()
    }
}

/// A builder for [`TrafficPolicySummary`](crate::types::TrafficPolicySummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TrafficPolicySummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::RrType>,
    pub(crate) latest_version: ::std::option::Option<i32>,
    pub(crate) traffic_policy_count: ::std::option::Option<i32>,
}
impl TrafficPolicySummaryBuilder {
    /// <p>The ID that Amazon Route 53 assigned to the traffic policy when you created it.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID that Amazon Route 53 assigned to the traffic policy when you created it.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID that Amazon Route 53 assigned to the traffic policy when you created it.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name that you specified for the traffic policy when you created it.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that you specified for the traffic policy when you created it.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name that you specified for the traffic policy when you created it.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The DNS type of the resource record sets that Amazon Route 53 creates when you use a traffic policy to create a traffic policy instance.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::RrType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DNS type of the resource record sets that Amazon Route 53 creates when you use a traffic policy to create a traffic policy instance.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RrType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The DNS type of the resource record sets that Amazon Route 53 creates when you use a traffic policy to create a traffic policy instance.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RrType> {
        &self.r#type
    }
    /// <p>The version number of the latest version of the traffic policy.</p>
    /// This field is required.
    pub fn latest_version(mut self, input: i32) -> Self {
        self.latest_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the latest version of the traffic policy.</p>
    pub fn set_latest_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.latest_version = input;
        self
    }
    /// <p>The version number of the latest version of the traffic policy.</p>
    pub fn get_latest_version(&self) -> &::std::option::Option<i32> {
        &self.latest_version
    }
    /// <p>The number of traffic policies that are associated with the current Amazon Web Services account.</p>
    /// This field is required.
    pub fn traffic_policy_count(mut self, input: i32) -> Self {
        self.traffic_policy_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of traffic policies that are associated with the current Amazon Web Services account.</p>
    pub fn set_traffic_policy_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.traffic_policy_count = input;
        self
    }
    /// <p>The number of traffic policies that are associated with the current Amazon Web Services account.</p>
    pub fn get_traffic_policy_count(&self) -> &::std::option::Option<i32> {
        &self.traffic_policy_count
    }
    /// Consumes the builder and constructs a [`TrafficPolicySummary`](crate::types::TrafficPolicySummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::TrafficPolicySummaryBuilder::id)
    /// - [`name`](crate::types::builders::TrafficPolicySummaryBuilder::name)
    /// - [`r#type`](crate::types::builders::TrafficPolicySummaryBuilder::type)
    /// - [`latest_version`](crate::types::builders::TrafficPolicySummaryBuilder::latest_version)
    /// - [`traffic_policy_count`](crate::types::builders::TrafficPolicySummaryBuilder::traffic_policy_count)
    pub fn build(self) -> ::std::result::Result<crate::types::TrafficPolicySummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TrafficPolicySummary {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building TrafficPolicySummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building TrafficPolicySummary",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building TrafficPolicySummary",
                )
            })?,
            latest_version: self.latest_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "latest_version",
                    "latest_version was not specified but it is required when building TrafficPolicySummary",
                )
            })?,
            traffic_policy_count: self.traffic_policy_count.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "traffic_policy_count",
                    "traffic_policy_count was not specified but it is required when building TrafficPolicySummary",
                )
            })?,
        })
    }
}
