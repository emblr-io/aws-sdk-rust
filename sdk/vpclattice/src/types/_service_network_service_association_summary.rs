// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information about an association between a service network and a service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceNetworkServiceAssociationSummary {
    /// <p>The ID of the association.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The status. If the deletion fails, try to delete again.</p>
    pub status: ::std::option::Option<crate::types::ServiceNetworkServiceAssociationStatus>,
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The account that created the association.</p>
    pub created_by: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the association was created, in ISO-8601 format.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ID of the service.</p>
    pub service_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the service.</p>
    pub service_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the service.</p>
    pub service_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the service network.</p>
    pub service_network_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the service network.</p>
    pub service_network_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the service network.</p>
    pub service_network_arn: ::std::option::Option<::std::string::String>,
    /// <p>The DNS information.</p>
    pub dns_entry: ::std::option::Option<crate::types::DnsEntry>,
    /// <p>The custom domain name of the service.</p>
    pub custom_domain_name: ::std::option::Option<::std::string::String>,
}
impl ServiceNetworkServiceAssociationSummary {
    /// <p>The ID of the association.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The status. If the deletion fails, try to delete again.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ServiceNetworkServiceAssociationStatus> {
        self.status.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The account that created the association.</p>
    pub fn created_by(&self) -> ::std::option::Option<&str> {
        self.created_by.as_deref()
    }
    /// <p>The date and time that the association was created, in ISO-8601 format.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The ID of the service.</p>
    pub fn service_id(&self) -> ::std::option::Option<&str> {
        self.service_id.as_deref()
    }
    /// <p>The name of the service.</p>
    pub fn service_name(&self) -> ::std::option::Option<&str> {
        self.service_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the service.</p>
    pub fn service_arn(&self) -> ::std::option::Option<&str> {
        self.service_arn.as_deref()
    }
    /// <p>The ID of the service network.</p>
    pub fn service_network_id(&self) -> ::std::option::Option<&str> {
        self.service_network_id.as_deref()
    }
    /// <p>The name of the service network.</p>
    pub fn service_network_name(&self) -> ::std::option::Option<&str> {
        self.service_network_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the service network.</p>
    pub fn service_network_arn(&self) -> ::std::option::Option<&str> {
        self.service_network_arn.as_deref()
    }
    /// <p>The DNS information.</p>
    pub fn dns_entry(&self) -> ::std::option::Option<&crate::types::DnsEntry> {
        self.dns_entry.as_ref()
    }
    /// <p>The custom domain name of the service.</p>
    pub fn custom_domain_name(&self) -> ::std::option::Option<&str> {
        self.custom_domain_name.as_deref()
    }
}
impl ServiceNetworkServiceAssociationSummary {
    /// Creates a new builder-style object to manufacture [`ServiceNetworkServiceAssociationSummary`](crate::types::ServiceNetworkServiceAssociationSummary).
    pub fn builder() -> crate::types::builders::ServiceNetworkServiceAssociationSummaryBuilder {
        crate::types::builders::ServiceNetworkServiceAssociationSummaryBuilder::default()
    }
}

/// A builder for [`ServiceNetworkServiceAssociationSummary`](crate::types::ServiceNetworkServiceAssociationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceNetworkServiceAssociationSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ServiceNetworkServiceAssociationStatus>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) service_id: ::std::option::Option<::std::string::String>,
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
    pub(crate) service_arn: ::std::option::Option<::std::string::String>,
    pub(crate) service_network_id: ::std::option::Option<::std::string::String>,
    pub(crate) service_network_name: ::std::option::Option<::std::string::String>,
    pub(crate) service_network_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dns_entry: ::std::option::Option<crate::types::DnsEntry>,
    pub(crate) custom_domain_name: ::std::option::Option<::std::string::String>,
}
impl ServiceNetworkServiceAssociationSummaryBuilder {
    /// <p>The ID of the association.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the association.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the association.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The status. If the deletion fails, try to delete again.</p>
    pub fn status(mut self, input: crate::types::ServiceNetworkServiceAssociationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status. If the deletion fails, try to delete again.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ServiceNetworkServiceAssociationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status. If the deletion fails, try to delete again.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ServiceNetworkServiceAssociationStatus> {
        &self.status
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the association.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The account that created the association.</p>
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account that created the association.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The account that created the association.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The date and time that the association was created, in ISO-8601 format.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the association was created, in ISO-8601 format.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the association was created, in ISO-8601 format.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The ID of the service.</p>
    pub fn service_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service.</p>
    pub fn set_service_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_id = input;
        self
    }
    /// <p>The ID of the service.</p>
    pub fn get_service_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_id
    }
    /// <p>The name of the service.</p>
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>The name of the service.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// <p>The Amazon Resource Name (ARN) of the service.</p>
    pub fn service_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service.</p>
    pub fn set_service_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service.</p>
    pub fn get_service_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_arn
    }
    /// <p>The ID of the service network.</p>
    pub fn service_network_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_network_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service network.</p>
    pub fn set_service_network_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_network_id = input;
        self
    }
    /// <p>The ID of the service network.</p>
    pub fn get_service_network_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_network_id
    }
    /// <p>The name of the service network.</p>
    pub fn service_network_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_network_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service network.</p>
    pub fn set_service_network_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_network_name = input;
        self
    }
    /// <p>The name of the service network.</p>
    pub fn get_service_network_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_network_name
    }
    /// <p>The Amazon Resource Name (ARN) of the service network.</p>
    pub fn service_network_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_network_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service network.</p>
    pub fn set_service_network_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_network_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the service network.</p>
    pub fn get_service_network_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_network_arn
    }
    /// <p>The DNS information.</p>
    pub fn dns_entry(mut self, input: crate::types::DnsEntry) -> Self {
        self.dns_entry = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DNS information.</p>
    pub fn set_dns_entry(mut self, input: ::std::option::Option<crate::types::DnsEntry>) -> Self {
        self.dns_entry = input;
        self
    }
    /// <p>The DNS information.</p>
    pub fn get_dns_entry(&self) -> &::std::option::Option<crate::types::DnsEntry> {
        &self.dns_entry
    }
    /// <p>The custom domain name of the service.</p>
    pub fn custom_domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom domain name of the service.</p>
    pub fn set_custom_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_domain_name = input;
        self
    }
    /// <p>The custom domain name of the service.</p>
    pub fn get_custom_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_domain_name
    }
    /// Consumes the builder and constructs a [`ServiceNetworkServiceAssociationSummary`](crate::types::ServiceNetworkServiceAssociationSummary).
    pub fn build(self) -> crate::types::ServiceNetworkServiceAssociationSummary {
        crate::types::ServiceNetworkServiceAssociationSummary {
            id: self.id,
            status: self.status,
            arn: self.arn,
            created_by: self.created_by,
            created_at: self.created_at,
            service_id: self.service_id,
            service_name: self.service_name,
            service_arn: self.service_arn,
            service_network_id: self.service_network_id,
            service_network_name: self.service_network_name,
            service_network_arn: self.service_network_arn,
            dns_entry: self.dns_entry,
            custom_domain_name: self.custom_domain_name,
        }
    }
}
