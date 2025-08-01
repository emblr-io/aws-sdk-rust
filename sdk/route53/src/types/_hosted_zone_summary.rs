// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>In the response to a <code>ListHostedZonesByVPC</code> request, the <code>HostedZoneSummaries</code> element contains one <code>HostedZoneSummary</code> element for each hosted zone that the specified Amazon VPC is associated with. Each <code>HostedZoneSummary</code> element contains the hosted zone name and ID, and information about who owns the hosted zone.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HostedZoneSummary {
    /// <p>The Route 53 hosted zone ID of a private hosted zone that the specified VPC is associated with.</p>
    pub hosted_zone_id: ::std::string::String,
    /// <p>The name of the private hosted zone, such as <code>example.com</code>.</p>
    pub name: ::std::string::String,
    /// <p>The owner of a private hosted zone that the specified VPC is associated with. The owner can be either an Amazon Web Services account or an Amazon Web Services service.</p>
    pub owner: ::std::option::Option<crate::types::HostedZoneOwner>,
}
impl HostedZoneSummary {
    /// <p>The Route 53 hosted zone ID of a private hosted zone that the specified VPC is associated with.</p>
    pub fn hosted_zone_id(&self) -> &str {
        use std::ops::Deref;
        self.hosted_zone_id.deref()
    }
    /// <p>The name of the private hosted zone, such as <code>example.com</code>.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The owner of a private hosted zone that the specified VPC is associated with. The owner can be either an Amazon Web Services account or an Amazon Web Services service.</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::HostedZoneOwner> {
        self.owner.as_ref()
    }
}
impl HostedZoneSummary {
    /// Creates a new builder-style object to manufacture [`HostedZoneSummary`](crate::types::HostedZoneSummary).
    pub fn builder() -> crate::types::builders::HostedZoneSummaryBuilder {
        crate::types::builders::HostedZoneSummaryBuilder::default()
    }
}

/// A builder for [`HostedZoneSummary`](crate::types::HostedZoneSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HostedZoneSummaryBuilder {
    pub(crate) hosted_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<crate::types::HostedZoneOwner>,
}
impl HostedZoneSummaryBuilder {
    /// <p>The Route 53 hosted zone ID of a private hosted zone that the specified VPC is associated with.</p>
    /// This field is required.
    pub fn hosted_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hosted_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Route 53 hosted zone ID of a private hosted zone that the specified VPC is associated with.</p>
    pub fn set_hosted_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hosted_zone_id = input;
        self
    }
    /// <p>The Route 53 hosted zone ID of a private hosted zone that the specified VPC is associated with.</p>
    pub fn get_hosted_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hosted_zone_id
    }
    /// <p>The name of the private hosted zone, such as <code>example.com</code>.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the private hosted zone, such as <code>example.com</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the private hosted zone, such as <code>example.com</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The owner of a private hosted zone that the specified VPC is associated with. The owner can be either an Amazon Web Services account or an Amazon Web Services service.</p>
    /// This field is required.
    pub fn owner(mut self, input: crate::types::HostedZoneOwner) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>The owner of a private hosted zone that the specified VPC is associated with. The owner can be either an Amazon Web Services account or an Amazon Web Services service.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::HostedZoneOwner>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of a private hosted zone that the specified VPC is associated with. The owner can be either an Amazon Web Services account or an Amazon Web Services service.</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::HostedZoneOwner> {
        &self.owner
    }
    /// Consumes the builder and constructs a [`HostedZoneSummary`](crate::types::HostedZoneSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`hosted_zone_id`](crate::types::builders::HostedZoneSummaryBuilder::hosted_zone_id)
    /// - [`name`](crate::types::builders::HostedZoneSummaryBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::HostedZoneSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::HostedZoneSummary {
            hosted_zone_id: self.hosted_zone_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "hosted_zone_id",
                    "hosted_zone_id was not specified but it is required when building HostedZoneSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building HostedZoneSummary",
                )
            })?,
            owner: self.owner,
        })
    }
}
