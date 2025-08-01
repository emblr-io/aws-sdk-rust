// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCustomDomainsOutput {
    /// <p>The App Runner subdomain of the App Runner service. The associated custom domain names are mapped to this target name.</p>
    pub dns_target: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the App Runner service whose associated custom domain names you want to describe.</p>
    pub service_arn: ::std::string::String,
    /// <p>A list of descriptions of custom domain names that are associated with the service. In a paginated request, the request returns up to <code>MaxResults</code> records per call.</p>
    pub custom_domains: ::std::vec::Vec<crate::types::CustomDomain>,
    /// <p>DNS Target records for the custom domains of this Amazon VPC.</p>
    pub vpc_dns_targets: ::std::vec::Vec<crate::types::VpcDnsTarget>,
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeCustomDomainsOutput {
    /// <p>The App Runner subdomain of the App Runner service. The associated custom domain names are mapped to this target name.</p>
    pub fn dns_target(&self) -> &str {
        use std::ops::Deref;
        self.dns_target.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the App Runner service whose associated custom domain names you want to describe.</p>
    pub fn service_arn(&self) -> &str {
        use std::ops::Deref;
        self.service_arn.deref()
    }
    /// <p>A list of descriptions of custom domain names that are associated with the service. In a paginated request, the request returns up to <code>MaxResults</code> records per call.</p>
    pub fn custom_domains(&self) -> &[crate::types::CustomDomain] {
        use std::ops::Deref;
        self.custom_domains.deref()
    }
    /// <p>DNS Target records for the custom domains of this Amazon VPC.</p>
    pub fn vpc_dns_targets(&self) -> &[crate::types::VpcDnsTarget] {
        use std::ops::Deref;
        self.vpc_dns_targets.deref()
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCustomDomainsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCustomDomainsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCustomDomainsOutput`](crate::operation::describe_custom_domains::DescribeCustomDomainsOutput).
    pub fn builder() -> crate::operation::describe_custom_domains::builders::DescribeCustomDomainsOutputBuilder {
        crate::operation::describe_custom_domains::builders::DescribeCustomDomainsOutputBuilder::default()
    }
}

/// A builder for [`DescribeCustomDomainsOutput`](crate::operation::describe_custom_domains::DescribeCustomDomainsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCustomDomainsOutputBuilder {
    pub(crate) dns_target: ::std::option::Option<::std::string::String>,
    pub(crate) service_arn: ::std::option::Option<::std::string::String>,
    pub(crate) custom_domains: ::std::option::Option<::std::vec::Vec<crate::types::CustomDomain>>,
    pub(crate) vpc_dns_targets: ::std::option::Option<::std::vec::Vec<crate::types::VpcDnsTarget>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeCustomDomainsOutputBuilder {
    /// <p>The App Runner subdomain of the App Runner service. The associated custom domain names are mapped to this target name.</p>
    /// This field is required.
    pub fn dns_target(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dns_target = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The App Runner subdomain of the App Runner service. The associated custom domain names are mapped to this target name.</p>
    pub fn set_dns_target(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dns_target = input;
        self
    }
    /// <p>The App Runner subdomain of the App Runner service. The associated custom domain names are mapped to this target name.</p>
    pub fn get_dns_target(&self) -> &::std::option::Option<::std::string::String> {
        &self.dns_target
    }
    /// <p>The Amazon Resource Name (ARN) of the App Runner service whose associated custom domain names you want to describe.</p>
    /// This field is required.
    pub fn service_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the App Runner service whose associated custom domain names you want to describe.</p>
    pub fn set_service_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the App Runner service whose associated custom domain names you want to describe.</p>
    pub fn get_service_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_arn
    }
    /// Appends an item to `custom_domains`.
    ///
    /// To override the contents of this collection use [`set_custom_domains`](Self::set_custom_domains).
    ///
    /// <p>A list of descriptions of custom domain names that are associated with the service. In a paginated request, the request returns up to <code>MaxResults</code> records per call.</p>
    pub fn custom_domains(mut self, input: crate::types::CustomDomain) -> Self {
        let mut v = self.custom_domains.unwrap_or_default();
        v.push(input);
        self.custom_domains = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of descriptions of custom domain names that are associated with the service. In a paginated request, the request returns up to <code>MaxResults</code> records per call.</p>
    pub fn set_custom_domains(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CustomDomain>>) -> Self {
        self.custom_domains = input;
        self
    }
    /// <p>A list of descriptions of custom domain names that are associated with the service. In a paginated request, the request returns up to <code>MaxResults</code> records per call.</p>
    pub fn get_custom_domains(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CustomDomain>> {
        &self.custom_domains
    }
    /// Appends an item to `vpc_dns_targets`.
    ///
    /// To override the contents of this collection use [`set_vpc_dns_targets`](Self::set_vpc_dns_targets).
    ///
    /// <p>DNS Target records for the custom domains of this Amazon VPC.</p>
    pub fn vpc_dns_targets(mut self, input: crate::types::VpcDnsTarget) -> Self {
        let mut v = self.vpc_dns_targets.unwrap_or_default();
        v.push(input);
        self.vpc_dns_targets = ::std::option::Option::Some(v);
        self
    }
    /// <p>DNS Target records for the custom domains of this Amazon VPC.</p>
    pub fn set_vpc_dns_targets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VpcDnsTarget>>) -> Self {
        self.vpc_dns_targets = input;
        self
    }
    /// <p>DNS Target records for the custom domains of this Amazon VPC.</p>
    pub fn get_vpc_dns_targets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VpcDnsTarget>> {
        &self.vpc_dns_targets
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
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
    /// Consumes the builder and constructs a [`DescribeCustomDomainsOutput`](crate::operation::describe_custom_domains::DescribeCustomDomainsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`dns_target`](crate::operation::describe_custom_domains::builders::DescribeCustomDomainsOutputBuilder::dns_target)
    /// - [`service_arn`](crate::operation::describe_custom_domains::builders::DescribeCustomDomainsOutputBuilder::service_arn)
    /// - [`custom_domains`](crate::operation::describe_custom_domains::builders::DescribeCustomDomainsOutputBuilder::custom_domains)
    /// - [`vpc_dns_targets`](crate::operation::describe_custom_domains::builders::DescribeCustomDomainsOutputBuilder::vpc_dns_targets)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_custom_domains::DescribeCustomDomainsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_custom_domains::DescribeCustomDomainsOutput {
            dns_target: self.dns_target.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dns_target",
                    "dns_target was not specified but it is required when building DescribeCustomDomainsOutput",
                )
            })?,
            service_arn: self.service_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_arn",
                    "service_arn was not specified but it is required when building DescribeCustomDomainsOutput",
                )
            })?,
            custom_domains: self.custom_domains.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "custom_domains",
                    "custom_domains was not specified but it is required when building DescribeCustomDomainsOutput",
                )
            })?,
            vpc_dns_targets: self.vpc_dns_targets.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "vpc_dns_targets",
                    "vpc_dns_targets was not specified but it is required when building DescribeCustomDomainsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
