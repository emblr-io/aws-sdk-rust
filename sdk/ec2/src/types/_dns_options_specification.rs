// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the DNS options for an endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DnsOptionsSpecification {
    /// <p>The DNS records created for the endpoint.</p>
    pub dns_record_ip_type: ::std::option::Option<crate::types::DnsRecordIpType>,
    /// <p>Indicates whether to enable private DNS only for inbound endpoints. This option is available only for services that support both gateway and interface endpoints. It routes traffic that originates from the VPC to the gateway endpoint and traffic that originates from on-premises to the interface endpoint.</p>
    pub private_dns_only_for_inbound_resolver_endpoint: ::std::option::Option<bool>,
}
impl DnsOptionsSpecification {
    /// <p>The DNS records created for the endpoint.</p>
    pub fn dns_record_ip_type(&self) -> ::std::option::Option<&crate::types::DnsRecordIpType> {
        self.dns_record_ip_type.as_ref()
    }
    /// <p>Indicates whether to enable private DNS only for inbound endpoints. This option is available only for services that support both gateway and interface endpoints. It routes traffic that originates from the VPC to the gateway endpoint and traffic that originates from on-premises to the interface endpoint.</p>
    pub fn private_dns_only_for_inbound_resolver_endpoint(&self) -> ::std::option::Option<bool> {
        self.private_dns_only_for_inbound_resolver_endpoint
    }
}
impl DnsOptionsSpecification {
    /// Creates a new builder-style object to manufacture [`DnsOptionsSpecification`](crate::types::DnsOptionsSpecification).
    pub fn builder() -> crate::types::builders::DnsOptionsSpecificationBuilder {
        crate::types::builders::DnsOptionsSpecificationBuilder::default()
    }
}

/// A builder for [`DnsOptionsSpecification`](crate::types::DnsOptionsSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DnsOptionsSpecificationBuilder {
    pub(crate) dns_record_ip_type: ::std::option::Option<crate::types::DnsRecordIpType>,
    pub(crate) private_dns_only_for_inbound_resolver_endpoint: ::std::option::Option<bool>,
}
impl DnsOptionsSpecificationBuilder {
    /// <p>The DNS records created for the endpoint.</p>
    pub fn dns_record_ip_type(mut self, input: crate::types::DnsRecordIpType) -> Self {
        self.dns_record_ip_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DNS records created for the endpoint.</p>
    pub fn set_dns_record_ip_type(mut self, input: ::std::option::Option<crate::types::DnsRecordIpType>) -> Self {
        self.dns_record_ip_type = input;
        self
    }
    /// <p>The DNS records created for the endpoint.</p>
    pub fn get_dns_record_ip_type(&self) -> &::std::option::Option<crate::types::DnsRecordIpType> {
        &self.dns_record_ip_type
    }
    /// <p>Indicates whether to enable private DNS only for inbound endpoints. This option is available only for services that support both gateway and interface endpoints. It routes traffic that originates from the VPC to the gateway endpoint and traffic that originates from on-premises to the interface endpoint.</p>
    pub fn private_dns_only_for_inbound_resolver_endpoint(mut self, input: bool) -> Self {
        self.private_dns_only_for_inbound_resolver_endpoint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to enable private DNS only for inbound endpoints. This option is available only for services that support both gateway and interface endpoints. It routes traffic that originates from the VPC to the gateway endpoint and traffic that originates from on-premises to the interface endpoint.</p>
    pub fn set_private_dns_only_for_inbound_resolver_endpoint(mut self, input: ::std::option::Option<bool>) -> Self {
        self.private_dns_only_for_inbound_resolver_endpoint = input;
        self
    }
    /// <p>Indicates whether to enable private DNS only for inbound endpoints. This option is available only for services that support both gateway and interface endpoints. It routes traffic that originates from the VPC to the gateway endpoint and traffic that originates from on-premises to the interface endpoint.</p>
    pub fn get_private_dns_only_for_inbound_resolver_endpoint(&self) -> &::std::option::Option<bool> {
        &self.private_dns_only_for_inbound_resolver_endpoint
    }
    /// Consumes the builder and constructs a [`DnsOptionsSpecification`](crate::types::DnsOptionsSpecification).
    pub fn build(self) -> crate::types::DnsOptionsSpecification {
        crate::types::DnsOptionsSpecification {
            dns_record_ip_type: self.dns_record_ip_type,
            private_dns_only_for_inbound_resolver_endpoint: self.private_dns_only_for_inbound_resolver_endpoint,
        }
    }
}
