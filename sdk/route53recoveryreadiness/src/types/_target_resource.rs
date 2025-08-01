// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The target resource that the Route 53 record points to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TargetResource {
    /// <p>The Network Load Balancer Resource.</p>
    pub nlb_resource: ::std::option::Option<crate::types::NlbResource>,
    /// <p>The Route 53 resource.</p>
    pub r53_resource: ::std::option::Option<crate::types::R53ResourceRecord>,
}
impl TargetResource {
    /// <p>The Network Load Balancer Resource.</p>
    pub fn nlb_resource(&self) -> ::std::option::Option<&crate::types::NlbResource> {
        self.nlb_resource.as_ref()
    }
    /// <p>The Route 53 resource.</p>
    pub fn r53_resource(&self) -> ::std::option::Option<&crate::types::R53ResourceRecord> {
        self.r53_resource.as_ref()
    }
}
impl TargetResource {
    /// Creates a new builder-style object to manufacture [`TargetResource`](crate::types::TargetResource).
    pub fn builder() -> crate::types::builders::TargetResourceBuilder {
        crate::types::builders::TargetResourceBuilder::default()
    }
}

/// A builder for [`TargetResource`](crate::types::TargetResource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TargetResourceBuilder {
    pub(crate) nlb_resource: ::std::option::Option<crate::types::NlbResource>,
    pub(crate) r53_resource: ::std::option::Option<crate::types::R53ResourceRecord>,
}
impl TargetResourceBuilder {
    /// <p>The Network Load Balancer Resource.</p>
    pub fn nlb_resource(mut self, input: crate::types::NlbResource) -> Self {
        self.nlb_resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Network Load Balancer Resource.</p>
    pub fn set_nlb_resource(mut self, input: ::std::option::Option<crate::types::NlbResource>) -> Self {
        self.nlb_resource = input;
        self
    }
    /// <p>The Network Load Balancer Resource.</p>
    pub fn get_nlb_resource(&self) -> &::std::option::Option<crate::types::NlbResource> {
        &self.nlb_resource
    }
    /// <p>The Route 53 resource.</p>
    pub fn r53_resource(mut self, input: crate::types::R53ResourceRecord) -> Self {
        self.r53_resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Route 53 resource.</p>
    pub fn set_r53_resource(mut self, input: ::std::option::Option<crate::types::R53ResourceRecord>) -> Self {
        self.r53_resource = input;
        self
    }
    /// <p>The Route 53 resource.</p>
    pub fn get_r53_resource(&self) -> &::std::option::Option<crate::types::R53ResourceRecord> {
        &self.r53_resource
    }
    /// Consumes the builder and constructs a [`TargetResource`](crate::types::TargetResource).
    pub fn build(self) -> crate::types::TargetResource {
        crate::types::TargetResource {
            nlb_resource: self.nlb_resource,
            r53_resource: self.r53_resource,
        }
    }
}
