// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVerifiedAccessEndpointInput {
    /// <p>The ID of the Verified Access group to associate the endpoint with.</p>
    pub verified_access_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of Verified Access endpoint to create.</p>
    pub endpoint_type: ::std::option::Option<crate::types::VerifiedAccessEndpointType>,
    /// <p>The type of attachment.</p>
    pub attachment_type: ::std::option::Option<crate::types::VerifiedAccessEndpointAttachmentType>,
    /// <p>The ARN of the public TLS/SSL certificate in Amazon Web Services Certificate Manager to associate with the endpoint. The CN in the certificate must match the DNS name your end users will use to reach your application.</p>
    pub domain_certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The DNS name for users to reach your application.</p>
    pub application_domain: ::std::option::Option<::std::string::String>,
    /// <p>A custom identifier that is prepended to the DNS name that is generated for the endpoint.</p>
    pub endpoint_domain_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The IDs of the security groups to associate with the Verified Access endpoint. Required if <code>AttachmentType</code> is set to <code>vpc</code>.</p>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The load balancer details. This parameter is required if the endpoint type is <code>load-balancer</code>.</p>
    pub load_balancer_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointLoadBalancerOptions>,
    /// <p>The network interface details. This parameter is required if the endpoint type is <code>network-interface</code>.</p>
    pub network_interface_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointEniOptions>,
    /// <p>A description for the Verified Access endpoint.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Verified Access policy document.</p>
    pub policy_document: ::std::option::Option<::std::string::String>,
    /// <p>The tags to assign to the Verified Access endpoint.</p>
    pub tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The options for server side encryption.</p>
    pub sse_specification: ::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest>,
    /// <p>The RDS details. This parameter is required if the endpoint type is <code>rds</code>.</p>
    pub rds_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointRdsOptions>,
    /// <p>The CIDR options. This parameter is required if the endpoint type is <code>cidr</code>.</p>
    pub cidr_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointCidrOptions>,
}
impl CreateVerifiedAccessEndpointInput {
    /// <p>The ID of the Verified Access group to associate the endpoint with.</p>
    pub fn verified_access_group_id(&self) -> ::std::option::Option<&str> {
        self.verified_access_group_id.as_deref()
    }
    /// <p>The type of Verified Access endpoint to create.</p>
    pub fn endpoint_type(&self) -> ::std::option::Option<&crate::types::VerifiedAccessEndpointType> {
        self.endpoint_type.as_ref()
    }
    /// <p>The type of attachment.</p>
    pub fn attachment_type(&self) -> ::std::option::Option<&crate::types::VerifiedAccessEndpointAttachmentType> {
        self.attachment_type.as_ref()
    }
    /// <p>The ARN of the public TLS/SSL certificate in Amazon Web Services Certificate Manager to associate with the endpoint. The CN in the certificate must match the DNS name your end users will use to reach your application.</p>
    pub fn domain_certificate_arn(&self) -> ::std::option::Option<&str> {
        self.domain_certificate_arn.as_deref()
    }
    /// <p>The DNS name for users to reach your application.</p>
    pub fn application_domain(&self) -> ::std::option::Option<&str> {
        self.application_domain.as_deref()
    }
    /// <p>A custom identifier that is prepended to the DNS name that is generated for the endpoint.</p>
    pub fn endpoint_domain_prefix(&self) -> ::std::option::Option<&str> {
        self.endpoint_domain_prefix.as_deref()
    }
    /// <p>The IDs of the security groups to associate with the Verified Access endpoint. Required if <code>AttachmentType</code> is set to <code>vpc</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The load balancer details. This parameter is required if the endpoint type is <code>load-balancer</code>.</p>
    pub fn load_balancer_options(&self) -> ::std::option::Option<&crate::types::CreateVerifiedAccessEndpointLoadBalancerOptions> {
        self.load_balancer_options.as_ref()
    }
    /// <p>The network interface details. This parameter is required if the endpoint type is <code>network-interface</code>.</p>
    pub fn network_interface_options(&self) -> ::std::option::Option<&crate::types::CreateVerifiedAccessEndpointEniOptions> {
        self.network_interface_options.as_ref()
    }
    /// <p>A description for the Verified Access endpoint.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Verified Access policy document.</p>
    pub fn policy_document(&self) -> ::std::option::Option<&str> {
        self.policy_document.as_deref()
    }
    /// <p>The tags to assign to the Verified Access endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_specifications.is_none()`.
    pub fn tag_specifications(&self) -> &[crate::types::TagSpecification] {
        self.tag_specifications.as_deref().unwrap_or_default()
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The options for server side encryption.</p>
    pub fn sse_specification(&self) -> ::std::option::Option<&crate::types::VerifiedAccessSseSpecificationRequest> {
        self.sse_specification.as_ref()
    }
    /// <p>The RDS details. This parameter is required if the endpoint type is <code>rds</code>.</p>
    pub fn rds_options(&self) -> ::std::option::Option<&crate::types::CreateVerifiedAccessEndpointRdsOptions> {
        self.rds_options.as_ref()
    }
    /// <p>The CIDR options. This parameter is required if the endpoint type is <code>cidr</code>.</p>
    pub fn cidr_options(&self) -> ::std::option::Option<&crate::types::CreateVerifiedAccessEndpointCidrOptions> {
        self.cidr_options.as_ref()
    }
}
impl CreateVerifiedAccessEndpointInput {
    /// Creates a new builder-style object to manufacture [`CreateVerifiedAccessEndpointInput`](crate::operation::create_verified_access_endpoint::CreateVerifiedAccessEndpointInput).
    pub fn builder() -> crate::operation::create_verified_access_endpoint::builders::CreateVerifiedAccessEndpointInputBuilder {
        crate::operation::create_verified_access_endpoint::builders::CreateVerifiedAccessEndpointInputBuilder::default()
    }
}

/// A builder for [`CreateVerifiedAccessEndpointInput`](crate::operation::create_verified_access_endpoint::CreateVerifiedAccessEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVerifiedAccessEndpointInputBuilder {
    pub(crate) verified_access_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_type: ::std::option::Option<crate::types::VerifiedAccessEndpointType>,
    pub(crate) attachment_type: ::std::option::Option<crate::types::VerifiedAccessEndpointAttachmentType>,
    pub(crate) domain_certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) application_domain: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_domain_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) load_balancer_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointLoadBalancerOptions>,
    pub(crate) network_interface_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointEniOptions>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) policy_document: ::std::option::Option<::std::string::String>,
    pub(crate) tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) sse_specification: ::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest>,
    pub(crate) rds_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointRdsOptions>,
    pub(crate) cidr_options: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointCidrOptions>,
}
impl CreateVerifiedAccessEndpointInputBuilder {
    /// <p>The ID of the Verified Access group to associate the endpoint with.</p>
    /// This field is required.
    pub fn verified_access_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.verified_access_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Verified Access group to associate the endpoint with.</p>
    pub fn set_verified_access_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.verified_access_group_id = input;
        self
    }
    /// <p>The ID of the Verified Access group to associate the endpoint with.</p>
    pub fn get_verified_access_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.verified_access_group_id
    }
    /// <p>The type of Verified Access endpoint to create.</p>
    /// This field is required.
    pub fn endpoint_type(mut self, input: crate::types::VerifiedAccessEndpointType) -> Self {
        self.endpoint_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of Verified Access endpoint to create.</p>
    pub fn set_endpoint_type(mut self, input: ::std::option::Option<crate::types::VerifiedAccessEndpointType>) -> Self {
        self.endpoint_type = input;
        self
    }
    /// <p>The type of Verified Access endpoint to create.</p>
    pub fn get_endpoint_type(&self) -> &::std::option::Option<crate::types::VerifiedAccessEndpointType> {
        &self.endpoint_type
    }
    /// <p>The type of attachment.</p>
    /// This field is required.
    pub fn attachment_type(mut self, input: crate::types::VerifiedAccessEndpointAttachmentType) -> Self {
        self.attachment_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of attachment.</p>
    pub fn set_attachment_type(mut self, input: ::std::option::Option<crate::types::VerifiedAccessEndpointAttachmentType>) -> Self {
        self.attachment_type = input;
        self
    }
    /// <p>The type of attachment.</p>
    pub fn get_attachment_type(&self) -> &::std::option::Option<crate::types::VerifiedAccessEndpointAttachmentType> {
        &self.attachment_type
    }
    /// <p>The ARN of the public TLS/SSL certificate in Amazon Web Services Certificate Manager to associate with the endpoint. The CN in the certificate must match the DNS name your end users will use to reach your application.</p>
    pub fn domain_certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the public TLS/SSL certificate in Amazon Web Services Certificate Manager to associate with the endpoint. The CN in the certificate must match the DNS name your end users will use to reach your application.</p>
    pub fn set_domain_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_certificate_arn = input;
        self
    }
    /// <p>The ARN of the public TLS/SSL certificate in Amazon Web Services Certificate Manager to associate with the endpoint. The CN in the certificate must match the DNS name your end users will use to reach your application.</p>
    pub fn get_domain_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_certificate_arn
    }
    /// <p>The DNS name for users to reach your application.</p>
    pub fn application_domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DNS name for users to reach your application.</p>
    pub fn set_application_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_domain = input;
        self
    }
    /// <p>The DNS name for users to reach your application.</p>
    pub fn get_application_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_domain
    }
    /// <p>A custom identifier that is prepended to the DNS name that is generated for the endpoint.</p>
    pub fn endpoint_domain_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.endpoint_domain_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A custom identifier that is prepended to the DNS name that is generated for the endpoint.</p>
    pub fn set_endpoint_domain_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.endpoint_domain_prefix = input;
        self
    }
    /// <p>A custom identifier that is prepended to the DNS name that is generated for the endpoint.</p>
    pub fn get_endpoint_domain_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.endpoint_domain_prefix
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>The IDs of the security groups to associate with the Verified Access endpoint. Required if <code>AttachmentType</code> is set to <code>vpc</code>.</p>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the security groups to associate with the Verified Access endpoint. Required if <code>AttachmentType</code> is set to <code>vpc</code>.</p>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>The IDs of the security groups to associate with the Verified Access endpoint. Required if <code>AttachmentType</code> is set to <code>vpc</code>.</p>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// <p>The load balancer details. This parameter is required if the endpoint type is <code>load-balancer</code>.</p>
    pub fn load_balancer_options(mut self, input: crate::types::CreateVerifiedAccessEndpointLoadBalancerOptions) -> Self {
        self.load_balancer_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The load balancer details. This parameter is required if the endpoint type is <code>load-balancer</code>.</p>
    pub fn set_load_balancer_options(mut self, input: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointLoadBalancerOptions>) -> Self {
        self.load_balancer_options = input;
        self
    }
    /// <p>The load balancer details. This parameter is required if the endpoint type is <code>load-balancer</code>.</p>
    pub fn get_load_balancer_options(&self) -> &::std::option::Option<crate::types::CreateVerifiedAccessEndpointLoadBalancerOptions> {
        &self.load_balancer_options
    }
    /// <p>The network interface details. This parameter is required if the endpoint type is <code>network-interface</code>.</p>
    pub fn network_interface_options(mut self, input: crate::types::CreateVerifiedAccessEndpointEniOptions) -> Self {
        self.network_interface_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The network interface details. This parameter is required if the endpoint type is <code>network-interface</code>.</p>
    pub fn set_network_interface_options(mut self, input: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointEniOptions>) -> Self {
        self.network_interface_options = input;
        self
    }
    /// <p>The network interface details. This parameter is required if the endpoint type is <code>network-interface</code>.</p>
    pub fn get_network_interface_options(&self) -> &::std::option::Option<crate::types::CreateVerifiedAccessEndpointEniOptions> {
        &self.network_interface_options
    }
    /// <p>A description for the Verified Access endpoint.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the Verified Access endpoint.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the Verified Access endpoint.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The Verified Access policy document.</p>
    pub fn policy_document(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_document = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Verified Access policy document.</p>
    pub fn set_policy_document(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_document = input;
        self
    }
    /// <p>The Verified Access policy document.</p>
    pub fn get_policy_document(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_document
    }
    /// Appends an item to `tag_specifications`.
    ///
    /// To override the contents of this collection use [`set_tag_specifications`](Self::set_tag_specifications).
    ///
    /// <p>The tags to assign to the Verified Access endpoint.</p>
    pub fn tag_specifications(mut self, input: crate::types::TagSpecification) -> Self {
        let mut v = self.tag_specifications.unwrap_or_default();
        v.push(input);
        self.tag_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to assign to the Verified Access endpoint.</p>
    pub fn set_tag_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>) -> Self {
        self.tag_specifications = input;
        self
    }
    /// <p>The tags to assign to the Verified Access endpoint.</p>
    pub fn get_tag_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>> {
        &self.tag_specifications
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive token that you provide to ensure idempotency of your modification request. For more information, see <a href="https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html">Ensuring idempotency</a>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>The options for server side encryption.</p>
    pub fn sse_specification(mut self, input: crate::types::VerifiedAccessSseSpecificationRequest) -> Self {
        self.sse_specification = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options for server side encryption.</p>
    pub fn set_sse_specification(mut self, input: ::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest>) -> Self {
        self.sse_specification = input;
        self
    }
    /// <p>The options for server side encryption.</p>
    pub fn get_sse_specification(&self) -> &::std::option::Option<crate::types::VerifiedAccessSseSpecificationRequest> {
        &self.sse_specification
    }
    /// <p>The RDS details. This parameter is required if the endpoint type is <code>rds</code>.</p>
    pub fn rds_options(mut self, input: crate::types::CreateVerifiedAccessEndpointRdsOptions) -> Self {
        self.rds_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The RDS details. This parameter is required if the endpoint type is <code>rds</code>.</p>
    pub fn set_rds_options(mut self, input: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointRdsOptions>) -> Self {
        self.rds_options = input;
        self
    }
    /// <p>The RDS details. This parameter is required if the endpoint type is <code>rds</code>.</p>
    pub fn get_rds_options(&self) -> &::std::option::Option<crate::types::CreateVerifiedAccessEndpointRdsOptions> {
        &self.rds_options
    }
    /// <p>The CIDR options. This parameter is required if the endpoint type is <code>cidr</code>.</p>
    pub fn cidr_options(mut self, input: crate::types::CreateVerifiedAccessEndpointCidrOptions) -> Self {
        self.cidr_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The CIDR options. This parameter is required if the endpoint type is <code>cidr</code>.</p>
    pub fn set_cidr_options(mut self, input: ::std::option::Option<crate::types::CreateVerifiedAccessEndpointCidrOptions>) -> Self {
        self.cidr_options = input;
        self
    }
    /// <p>The CIDR options. This parameter is required if the endpoint type is <code>cidr</code>.</p>
    pub fn get_cidr_options(&self) -> &::std::option::Option<crate::types::CreateVerifiedAccessEndpointCidrOptions> {
        &self.cidr_options
    }
    /// Consumes the builder and constructs a [`CreateVerifiedAccessEndpointInput`](crate::operation::create_verified_access_endpoint::CreateVerifiedAccessEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_verified_access_endpoint::CreateVerifiedAccessEndpointInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_verified_access_endpoint::CreateVerifiedAccessEndpointInput {
            verified_access_group_id: self.verified_access_group_id,
            endpoint_type: self.endpoint_type,
            attachment_type: self.attachment_type,
            domain_certificate_arn: self.domain_certificate_arn,
            application_domain: self.application_domain,
            endpoint_domain_prefix: self.endpoint_domain_prefix,
            security_group_ids: self.security_group_ids,
            load_balancer_options: self.load_balancer_options,
            network_interface_options: self.network_interface_options,
            description: self.description,
            policy_document: self.policy_document,
            tag_specifications: self.tag_specifications,
            client_token: self.client_token,
            dry_run: self.dry_run,
            sse_specification: self.sse_specification,
            rds_options: self.rds_options,
            cidr_options: self.cidr_options,
        })
    }
}
