// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The capacity usage summary of the resources used by the <code>ReferenceSets</code> in a firewall.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CapacityUsageSummary {
    /// <p>Describes the capacity usage of the CIDR blocks used by the IP set references in a firewall.</p>
    pub cidrs: ::std::option::Option<crate::types::CidrSummary>,
}
impl CapacityUsageSummary {
    /// <p>Describes the capacity usage of the CIDR blocks used by the IP set references in a firewall.</p>
    pub fn cidrs(&self) -> ::std::option::Option<&crate::types::CidrSummary> {
        self.cidrs.as_ref()
    }
}
impl CapacityUsageSummary {
    /// Creates a new builder-style object to manufacture [`CapacityUsageSummary`](crate::types::CapacityUsageSummary).
    pub fn builder() -> crate::types::builders::CapacityUsageSummaryBuilder {
        crate::types::builders::CapacityUsageSummaryBuilder::default()
    }
}

/// A builder for [`CapacityUsageSummary`](crate::types::CapacityUsageSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CapacityUsageSummaryBuilder {
    pub(crate) cidrs: ::std::option::Option<crate::types::CidrSummary>,
}
impl CapacityUsageSummaryBuilder {
    /// <p>Describes the capacity usage of the CIDR blocks used by the IP set references in a firewall.</p>
    pub fn cidrs(mut self, input: crate::types::CidrSummary) -> Self {
        self.cidrs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the capacity usage of the CIDR blocks used by the IP set references in a firewall.</p>
    pub fn set_cidrs(mut self, input: ::std::option::Option<crate::types::CidrSummary>) -> Self {
        self.cidrs = input;
        self
    }
    /// <p>Describes the capacity usage of the CIDR blocks used by the IP set references in a firewall.</p>
    pub fn get_cidrs(&self) -> &::std::option::Option<crate::types::CidrSummary> {
        &self.cidrs
    }
    /// Consumes the builder and constructs a [`CapacityUsageSummary`](crate::types::CapacityUsageSummary).
    pub fn build(self) -> crate::types::CapacityUsageSummary {
        crate::types::CapacityUsageSummary { cidrs: self.cidrs }
    }
}
