// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>User pool configuration for delivery of SMS messages with Amazon Simple Notification Service. To send SMS messages with Amazon SNS in the Amazon Web Services Region that you want, the Amazon Cognito user pool uses an Identity and Access Management (IAM) role in your Amazon Web Services account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SmsConfigurationType {
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS caller. This is the ARN of the IAM role in your Amazon Web Services account that Amazon Cognito will use to send SMS messages. SMS messages are subject to a <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html">spending limit</a>.</p>
    pub sns_caller_arn: ::std::string::String,
    /// <p>The external ID provides additional security for your IAM role. You can use an <code>ExternalId</code> with the IAM role that you use with Amazon SNS to send SMS messages for your user pool. If you provide an <code>ExternalId</code>, your Amazon Cognito user pool includes it in the request to assume your IAM role. You can configure the role trust policy to require that Amazon Cognito, and any principal, provide the <code>ExternalID</code>. If you use the Amazon Cognito Management Console to create a role for SMS multi-factor authentication (MFA), Amazon Cognito creates a role with the required permissions and a trust policy that demonstrates use of the <code>ExternalId</code>.</p>
    /// <p>For more information about the <code>ExternalId</code> of a role, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html">How to use an external ID when granting access to your Amazon Web Services resources to a third party</a>.</p>
    pub external_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services Region to use with Amazon SNS integration. You can choose the same Region as your user pool, or a supported <b>Legacy Amazon SNS alternate Region</b>.</p>
    /// <p>Amazon Cognito resources in the Asia Pacific (Seoul) Amazon Web Services Region must use your Amazon SNS configuration in the Asia Pacific (Tokyo) Region. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-sms-settings.html">SMS message settings for Amazon Cognito user pools</a>.</p>
    pub sns_region: ::std::option::Option<::std::string::String>,
}
impl SmsConfigurationType {
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS caller. This is the ARN of the IAM role in your Amazon Web Services account that Amazon Cognito will use to send SMS messages. SMS messages are subject to a <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html">spending limit</a>.</p>
    pub fn sns_caller_arn(&self) -> &str {
        use std::ops::Deref;
        self.sns_caller_arn.deref()
    }
    /// <p>The external ID provides additional security for your IAM role. You can use an <code>ExternalId</code> with the IAM role that you use with Amazon SNS to send SMS messages for your user pool. If you provide an <code>ExternalId</code>, your Amazon Cognito user pool includes it in the request to assume your IAM role. You can configure the role trust policy to require that Amazon Cognito, and any principal, provide the <code>ExternalID</code>. If you use the Amazon Cognito Management Console to create a role for SMS multi-factor authentication (MFA), Amazon Cognito creates a role with the required permissions and a trust policy that demonstrates use of the <code>ExternalId</code>.</p>
    /// <p>For more information about the <code>ExternalId</code> of a role, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html">How to use an external ID when granting access to your Amazon Web Services resources to a third party</a>.</p>
    pub fn external_id(&self) -> ::std::option::Option<&str> {
        self.external_id.as_deref()
    }
    /// <p>The Amazon Web Services Region to use with Amazon SNS integration. You can choose the same Region as your user pool, or a supported <b>Legacy Amazon SNS alternate Region</b>.</p>
    /// <p>Amazon Cognito resources in the Asia Pacific (Seoul) Amazon Web Services Region must use your Amazon SNS configuration in the Asia Pacific (Tokyo) Region. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-sms-settings.html">SMS message settings for Amazon Cognito user pools</a>.</p>
    pub fn sns_region(&self) -> ::std::option::Option<&str> {
        self.sns_region.as_deref()
    }
}
impl SmsConfigurationType {
    /// Creates a new builder-style object to manufacture [`SmsConfigurationType`](crate::types::SmsConfigurationType).
    pub fn builder() -> crate::types::builders::SmsConfigurationTypeBuilder {
        crate::types::builders::SmsConfigurationTypeBuilder::default()
    }
}

/// A builder for [`SmsConfigurationType`](crate::types::SmsConfigurationType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SmsConfigurationTypeBuilder {
    pub(crate) sns_caller_arn: ::std::option::Option<::std::string::String>,
    pub(crate) external_id: ::std::option::Option<::std::string::String>,
    pub(crate) sns_region: ::std::option::Option<::std::string::String>,
}
impl SmsConfigurationTypeBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS caller. This is the ARN of the IAM role in your Amazon Web Services account that Amazon Cognito will use to send SMS messages. SMS messages are subject to a <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html">spending limit</a>.</p>
    /// This field is required.
    pub fn sns_caller_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sns_caller_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS caller. This is the ARN of the IAM role in your Amazon Web Services account that Amazon Cognito will use to send SMS messages. SMS messages are subject to a <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html">spending limit</a>.</p>
    pub fn set_sns_caller_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sns_caller_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS caller. This is the ARN of the IAM role in your Amazon Web Services account that Amazon Cognito will use to send SMS messages. SMS messages are subject to a <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html">spending limit</a>.</p>
    pub fn get_sns_caller_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.sns_caller_arn
    }
    /// <p>The external ID provides additional security for your IAM role. You can use an <code>ExternalId</code> with the IAM role that you use with Amazon SNS to send SMS messages for your user pool. If you provide an <code>ExternalId</code>, your Amazon Cognito user pool includes it in the request to assume your IAM role. You can configure the role trust policy to require that Amazon Cognito, and any principal, provide the <code>ExternalID</code>. If you use the Amazon Cognito Management Console to create a role for SMS multi-factor authentication (MFA), Amazon Cognito creates a role with the required permissions and a trust policy that demonstrates use of the <code>ExternalId</code>.</p>
    /// <p>For more information about the <code>ExternalId</code> of a role, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html">How to use an external ID when granting access to your Amazon Web Services resources to a third party</a>.</p>
    pub fn external_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.external_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The external ID provides additional security for your IAM role. You can use an <code>ExternalId</code> with the IAM role that you use with Amazon SNS to send SMS messages for your user pool. If you provide an <code>ExternalId</code>, your Amazon Cognito user pool includes it in the request to assume your IAM role. You can configure the role trust policy to require that Amazon Cognito, and any principal, provide the <code>ExternalID</code>. If you use the Amazon Cognito Management Console to create a role for SMS multi-factor authentication (MFA), Amazon Cognito creates a role with the required permissions and a trust policy that demonstrates use of the <code>ExternalId</code>.</p>
    /// <p>For more information about the <code>ExternalId</code> of a role, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html">How to use an external ID when granting access to your Amazon Web Services resources to a third party</a>.</p>
    pub fn set_external_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.external_id = input;
        self
    }
    /// <p>The external ID provides additional security for your IAM role. You can use an <code>ExternalId</code> with the IAM role that you use with Amazon SNS to send SMS messages for your user pool. If you provide an <code>ExternalId</code>, your Amazon Cognito user pool includes it in the request to assume your IAM role. You can configure the role trust policy to require that Amazon Cognito, and any principal, provide the <code>ExternalID</code>. If you use the Amazon Cognito Management Console to create a role for SMS multi-factor authentication (MFA), Amazon Cognito creates a role with the required permissions and a trust policy that demonstrates use of the <code>ExternalId</code>.</p>
    /// <p>For more information about the <code>ExternalId</code> of a role, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html">How to use an external ID when granting access to your Amazon Web Services resources to a third party</a>.</p>
    pub fn get_external_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.external_id
    }
    /// <p>The Amazon Web Services Region to use with Amazon SNS integration. You can choose the same Region as your user pool, or a supported <b>Legacy Amazon SNS alternate Region</b>.</p>
    /// <p>Amazon Cognito resources in the Asia Pacific (Seoul) Amazon Web Services Region must use your Amazon SNS configuration in the Asia Pacific (Tokyo) Region. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-sms-settings.html">SMS message settings for Amazon Cognito user pools</a>.</p>
    pub fn sns_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sns_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region to use with Amazon SNS integration. You can choose the same Region as your user pool, or a supported <b>Legacy Amazon SNS alternate Region</b>.</p>
    /// <p>Amazon Cognito resources in the Asia Pacific (Seoul) Amazon Web Services Region must use your Amazon SNS configuration in the Asia Pacific (Tokyo) Region. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-sms-settings.html">SMS message settings for Amazon Cognito user pools</a>.</p>
    pub fn set_sns_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sns_region = input;
        self
    }
    /// <p>The Amazon Web Services Region to use with Amazon SNS integration. You can choose the same Region as your user pool, or a supported <b>Legacy Amazon SNS alternate Region</b>.</p>
    /// <p>Amazon Cognito resources in the Asia Pacific (Seoul) Amazon Web Services Region must use your Amazon SNS configuration in the Asia Pacific (Tokyo) Region. For more information, see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-sms-settings.html">SMS message settings for Amazon Cognito user pools</a>.</p>
    pub fn get_sns_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.sns_region
    }
    /// Consumes the builder and constructs a [`SmsConfigurationType`](crate::types::SmsConfigurationType).
    /// This method will fail if any of the following fields are not set:
    /// - [`sns_caller_arn`](crate::types::builders::SmsConfigurationTypeBuilder::sns_caller_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::SmsConfigurationType, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SmsConfigurationType {
            sns_caller_arn: self.sns_caller_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sns_caller_arn",
                    "sns_caller_arn was not specified but it is required when building SmsConfigurationType",
                )
            })?,
            external_id: self.external_id,
            sns_region: self.sns_region,
        })
    }
}
