// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetKxEnvironmentOutput {
    /// <p>The name of the kdb environment.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the kdb environment.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the AWS account that is used to create the kdb environment.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the kdb environment.</p>
    pub status: ::std::option::Option<crate::types::EnvironmentStatus>,
    /// <p>The status of the network configuration.</p>
    pub tgw_status: ::std::option::Option<crate::types::TgwStatus>,
    /// <p>The status of DNS configuration.</p>
    pub dns_status: ::std::option::Option<crate::types::DnsStatus>,
    /// <p>Specifies the error message that appears if a flow fails.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>A description for the kdb environment.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ARN identifier of the environment.</p>
    pub environment_arn: ::std::option::Option<::std::string::String>,
    /// <p>The KMS key ID to encrypt your data in the FinSpace environment.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the AWS environment infrastructure account.</p>
    pub dedicated_service_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The structure of the transit gateway and network configuration that is used to connect the kdb environment to an internal network.</p>
    pub transit_gateway_configuration: ::std::option::Option<crate::types::TransitGatewayConfiguration>,
    /// <p>A list of DNS server name and server IP. This is used to set up Route-53 outbound resolvers.</p>
    pub custom_dns_configuration: ::std::option::Option<::std::vec::Vec<crate::types::CustomDnsServer>>,
    /// <p>The timestamp at which the kdb environment was created in FinSpace.</p>
    pub creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp at which the kdb environment was updated.</p>
    pub update_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The identifier of the availability zones where subnets for the environment are created.</p>
    pub availability_zone_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) of the certificate authority of the kdb environment.</p>
    pub certificate_authority_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetKxEnvironmentOutput {
    /// <p>The name of the kdb environment.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The unique identifier of the AWS account that is used to create the kdb environment.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The status of the kdb environment.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::EnvironmentStatus> {
        self.status.as_ref()
    }
    /// <p>The status of the network configuration.</p>
    pub fn tgw_status(&self) -> ::std::option::Option<&crate::types::TgwStatus> {
        self.tgw_status.as_ref()
    }
    /// <p>The status of DNS configuration.</p>
    pub fn dns_status(&self) -> ::std::option::Option<&crate::types::DnsStatus> {
        self.dns_status.as_ref()
    }
    /// <p>Specifies the error message that appears if a flow fails.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>A description for the kdb environment.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ARN identifier of the environment.</p>
    pub fn environment_arn(&self) -> ::std::option::Option<&str> {
        self.environment_arn.as_deref()
    }
    /// <p>The KMS key ID to encrypt your data in the FinSpace environment.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>A unique identifier for the AWS environment infrastructure account.</p>
    pub fn dedicated_service_account_id(&self) -> ::std::option::Option<&str> {
        self.dedicated_service_account_id.as_deref()
    }
    /// <p>The structure of the transit gateway and network configuration that is used to connect the kdb environment to an internal network.</p>
    pub fn transit_gateway_configuration(&self) -> ::std::option::Option<&crate::types::TransitGatewayConfiguration> {
        self.transit_gateway_configuration.as_ref()
    }
    /// <p>A list of DNS server name and server IP. This is used to set up Route-53 outbound resolvers.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.custom_dns_configuration.is_none()`.
    pub fn custom_dns_configuration(&self) -> &[crate::types::CustomDnsServer] {
        self.custom_dns_configuration.as_deref().unwrap_or_default()
    }
    /// <p>The timestamp at which the kdb environment was created in FinSpace.</p>
    pub fn creation_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_timestamp.as_ref()
    }
    /// <p>The timestamp at which the kdb environment was updated.</p>
    pub fn update_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.update_timestamp.as_ref()
    }
    /// <p>The identifier of the availability zones where subnets for the environment are created.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zone_ids.is_none()`.
    pub fn availability_zone_ids(&self) -> &[::std::string::String] {
        self.availability_zone_ids.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate authority of the kdb environment.</p>
    pub fn certificate_authority_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_authority_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetKxEnvironmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetKxEnvironmentOutput {
    /// Creates a new builder-style object to manufacture [`GetKxEnvironmentOutput`](crate::operation::get_kx_environment::GetKxEnvironmentOutput).
    pub fn builder() -> crate::operation::get_kx_environment::builders::GetKxEnvironmentOutputBuilder {
        crate::operation::get_kx_environment::builders::GetKxEnvironmentOutputBuilder::default()
    }
}

/// A builder for [`GetKxEnvironmentOutput`](crate::operation::get_kx_environment::GetKxEnvironmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetKxEnvironmentOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::EnvironmentStatus>,
    pub(crate) tgw_status: ::std::option::Option<crate::types::TgwStatus>,
    pub(crate) dns_status: ::std::option::Option<crate::types::DnsStatus>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) environment_arn: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) dedicated_service_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) transit_gateway_configuration: ::std::option::Option<crate::types::TransitGatewayConfiguration>,
    pub(crate) custom_dns_configuration: ::std::option::Option<::std::vec::Vec<crate::types::CustomDnsServer>>,
    pub(crate) creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) availability_zone_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) certificate_authority_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetKxEnvironmentOutputBuilder {
    /// <p>The name of the kdb environment.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the kdb environment.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the kdb environment.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>A unique identifier for the kdb environment.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>The unique identifier of the AWS account that is used to create the kdb environment.</p>
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the AWS account that is used to create the kdb environment.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The unique identifier of the AWS account that is used to create the kdb environment.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The status of the kdb environment.</p>
    pub fn status(mut self, input: crate::types::EnvironmentStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the kdb environment.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::EnvironmentStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the kdb environment.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::EnvironmentStatus> {
        &self.status
    }
    /// <p>The status of the network configuration.</p>
    pub fn tgw_status(mut self, input: crate::types::TgwStatus) -> Self {
        self.tgw_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the network configuration.</p>
    pub fn set_tgw_status(mut self, input: ::std::option::Option<crate::types::TgwStatus>) -> Self {
        self.tgw_status = input;
        self
    }
    /// <p>The status of the network configuration.</p>
    pub fn get_tgw_status(&self) -> &::std::option::Option<crate::types::TgwStatus> {
        &self.tgw_status
    }
    /// <p>The status of DNS configuration.</p>
    pub fn dns_status(mut self, input: crate::types::DnsStatus) -> Self {
        self.dns_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of DNS configuration.</p>
    pub fn set_dns_status(mut self, input: ::std::option::Option<crate::types::DnsStatus>) -> Self {
        self.dns_status = input;
        self
    }
    /// <p>The status of DNS configuration.</p>
    pub fn get_dns_status(&self) -> &::std::option::Option<crate::types::DnsStatus> {
        &self.dns_status
    }
    /// <p>Specifies the error message that appears if a flow fails.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the error message that appears if a flow fails.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>Specifies the error message that appears if a flow fails.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>A description for the kdb environment.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the kdb environment.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the kdb environment.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ARN identifier of the environment.</p>
    pub fn environment_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN identifier of the environment.</p>
    pub fn set_environment_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_arn = input;
        self
    }
    /// <p>The ARN identifier of the environment.</p>
    pub fn get_environment_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_arn
    }
    /// <p>The KMS key ID to encrypt your data in the FinSpace environment.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS key ID to encrypt your data in the FinSpace environment.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The KMS key ID to encrypt your data in the FinSpace environment.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>A unique identifier for the AWS environment infrastructure account.</p>
    pub fn dedicated_service_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dedicated_service_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the AWS environment infrastructure account.</p>
    pub fn set_dedicated_service_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dedicated_service_account_id = input;
        self
    }
    /// <p>A unique identifier for the AWS environment infrastructure account.</p>
    pub fn get_dedicated_service_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dedicated_service_account_id
    }
    /// <p>The structure of the transit gateway and network configuration that is used to connect the kdb environment to an internal network.</p>
    pub fn transit_gateway_configuration(mut self, input: crate::types::TransitGatewayConfiguration) -> Self {
        self.transit_gateway_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The structure of the transit gateway and network configuration that is used to connect the kdb environment to an internal network.</p>
    pub fn set_transit_gateway_configuration(mut self, input: ::std::option::Option<crate::types::TransitGatewayConfiguration>) -> Self {
        self.transit_gateway_configuration = input;
        self
    }
    /// <p>The structure of the transit gateway and network configuration that is used to connect the kdb environment to an internal network.</p>
    pub fn get_transit_gateway_configuration(&self) -> &::std::option::Option<crate::types::TransitGatewayConfiguration> {
        &self.transit_gateway_configuration
    }
    /// Appends an item to `custom_dns_configuration`.
    ///
    /// To override the contents of this collection use [`set_custom_dns_configuration`](Self::set_custom_dns_configuration).
    ///
    /// <p>A list of DNS server name and server IP. This is used to set up Route-53 outbound resolvers.</p>
    pub fn custom_dns_configuration(mut self, input: crate::types::CustomDnsServer) -> Self {
        let mut v = self.custom_dns_configuration.unwrap_or_default();
        v.push(input);
        self.custom_dns_configuration = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of DNS server name and server IP. This is used to set up Route-53 outbound resolvers.</p>
    pub fn set_custom_dns_configuration(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CustomDnsServer>>) -> Self {
        self.custom_dns_configuration = input;
        self
    }
    /// <p>A list of DNS server name and server IP. This is used to set up Route-53 outbound resolvers.</p>
    pub fn get_custom_dns_configuration(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CustomDnsServer>> {
        &self.custom_dns_configuration
    }
    /// <p>The timestamp at which the kdb environment was created in FinSpace.</p>
    pub fn creation_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the kdb environment was created in FinSpace.</p>
    pub fn set_creation_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_timestamp = input;
        self
    }
    /// <p>The timestamp at which the kdb environment was created in FinSpace.</p>
    pub fn get_creation_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_timestamp
    }
    /// <p>The timestamp at which the kdb environment was updated.</p>
    pub fn update_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the kdb environment was updated.</p>
    pub fn set_update_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_timestamp = input;
        self
    }
    /// <p>The timestamp at which the kdb environment was updated.</p>
    pub fn get_update_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_timestamp
    }
    /// Appends an item to `availability_zone_ids`.
    ///
    /// To override the contents of this collection use [`set_availability_zone_ids`](Self::set_availability_zone_ids).
    ///
    /// <p>The identifier of the availability zones where subnets for the environment are created.</p>
    pub fn availability_zone_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zone_ids.unwrap_or_default();
        v.push(input.into());
        self.availability_zone_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The identifier of the availability zones where subnets for the environment are created.</p>
    pub fn set_availability_zone_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zone_ids = input;
        self
    }
    /// <p>The identifier of the availability zones where subnets for the environment are created.</p>
    pub fn get_availability_zone_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zone_ids
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate authority of the kdb environment.</p>
    pub fn certificate_authority_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_authority_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate authority of the kdb environment.</p>
    pub fn set_certificate_authority_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_authority_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate authority of the kdb environment.</p>
    pub fn get_certificate_authority_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_authority_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetKxEnvironmentOutput`](crate::operation::get_kx_environment::GetKxEnvironmentOutput).
    pub fn build(self) -> crate::operation::get_kx_environment::GetKxEnvironmentOutput {
        crate::operation::get_kx_environment::GetKxEnvironmentOutput {
            name: self.name,
            environment_id: self.environment_id,
            aws_account_id: self.aws_account_id,
            status: self.status,
            tgw_status: self.tgw_status,
            dns_status: self.dns_status,
            error_message: self.error_message,
            description: self.description,
            environment_arn: self.environment_arn,
            kms_key_id: self.kms_key_id,
            dedicated_service_account_id: self.dedicated_service_account_id,
            transit_gateway_configuration: self.transit_gateway_configuration,
            custom_dns_configuration: self.custom_dns_configuration,
            creation_timestamp: self.creation_timestamp,
            update_timestamp: self.update_timestamp,
            availability_zone_ids: self.availability_zone_ids,
            certificate_authority_arn: self.certificate_authority_arn,
            _request_id: self._request_id,
        }
    }
}
