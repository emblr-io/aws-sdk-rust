// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRedshiftIdcApplicationInput {
    /// <p>The Amazon resource name (ARN) of the IAM Identity Center instance where Amazon Redshift creates a new managed application.</p>
    pub idc_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Redshift application in IAM Identity Center.</p>
    pub redshift_idc_application_name: ::std::option::Option<::std::string::String>,
    /// <p>The namespace for the Amazon Redshift IAM Identity Center application instance. It determines which managed application verifies the connection token.</p>
    pub identity_namespace: ::std::option::Option<::std::string::String>,
    /// <p>The display name for the Amazon Redshift IAM Identity Center application instance. It appears in the console.</p>
    pub idc_display_name: ::std::option::Option<::std::string::String>,
    /// <p>The IAM role ARN for the Amazon Redshift IAM Identity Center application instance. It has the required permissions to be assumed and invoke the IDC Identity Center API.</p>
    pub iam_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The token issuer list for the Amazon Redshift IAM Identity Center application instance.</p>
    pub authorized_token_issuer_list: ::std::option::Option<::std::vec::Vec<crate::types::AuthorizedTokenIssuer>>,
    /// <p>A collection of service integrations for the Redshift IAM Identity Center application.</p>
    pub service_integrations: ::std::option::Option<::std::vec::Vec<crate::types::ServiceIntegrationsUnion>>,
}
impl CreateRedshiftIdcApplicationInput {
    /// <p>The Amazon resource name (ARN) of the IAM Identity Center instance where Amazon Redshift creates a new managed application.</p>
    pub fn idc_instance_arn(&self) -> ::std::option::Option<&str> {
        self.idc_instance_arn.as_deref()
    }
    /// <p>The name of the Redshift application in IAM Identity Center.</p>
    pub fn redshift_idc_application_name(&self) -> ::std::option::Option<&str> {
        self.redshift_idc_application_name.as_deref()
    }
    /// <p>The namespace for the Amazon Redshift IAM Identity Center application instance. It determines which managed application verifies the connection token.</p>
    pub fn identity_namespace(&self) -> ::std::option::Option<&str> {
        self.identity_namespace.as_deref()
    }
    /// <p>The display name for the Amazon Redshift IAM Identity Center application instance. It appears in the console.</p>
    pub fn idc_display_name(&self) -> ::std::option::Option<&str> {
        self.idc_display_name.as_deref()
    }
    /// <p>The IAM role ARN for the Amazon Redshift IAM Identity Center application instance. It has the required permissions to be assumed and invoke the IDC Identity Center API.</p>
    pub fn iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.iam_role_arn.as_deref()
    }
    /// <p>The token issuer list for the Amazon Redshift IAM Identity Center application instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.authorized_token_issuer_list.is_none()`.
    pub fn authorized_token_issuer_list(&self) -> &[crate::types::AuthorizedTokenIssuer] {
        self.authorized_token_issuer_list.as_deref().unwrap_or_default()
    }
    /// <p>A collection of service integrations for the Redshift IAM Identity Center application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.service_integrations.is_none()`.
    pub fn service_integrations(&self) -> &[crate::types::ServiceIntegrationsUnion] {
        self.service_integrations.as_deref().unwrap_or_default()
    }
}
impl CreateRedshiftIdcApplicationInput {
    /// Creates a new builder-style object to manufacture [`CreateRedshiftIdcApplicationInput`](crate::operation::create_redshift_idc_application::CreateRedshiftIdcApplicationInput).
    pub fn builder() -> crate::operation::create_redshift_idc_application::builders::CreateRedshiftIdcApplicationInputBuilder {
        crate::operation::create_redshift_idc_application::builders::CreateRedshiftIdcApplicationInputBuilder::default()
    }
}

/// A builder for [`CreateRedshiftIdcApplicationInput`](crate::operation::create_redshift_idc_application::CreateRedshiftIdcApplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRedshiftIdcApplicationInputBuilder {
    pub(crate) idc_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) redshift_idc_application_name: ::std::option::Option<::std::string::String>,
    pub(crate) identity_namespace: ::std::option::Option<::std::string::String>,
    pub(crate) idc_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) authorized_token_issuer_list: ::std::option::Option<::std::vec::Vec<crate::types::AuthorizedTokenIssuer>>,
    pub(crate) service_integrations: ::std::option::Option<::std::vec::Vec<crate::types::ServiceIntegrationsUnion>>,
}
impl CreateRedshiftIdcApplicationInputBuilder {
    /// <p>The Amazon resource name (ARN) of the IAM Identity Center instance where Amazon Redshift creates a new managed application.</p>
    /// This field is required.
    pub fn idc_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.idc_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon resource name (ARN) of the IAM Identity Center instance where Amazon Redshift creates a new managed application.</p>
    pub fn set_idc_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.idc_instance_arn = input;
        self
    }
    /// <p>The Amazon resource name (ARN) of the IAM Identity Center instance where Amazon Redshift creates a new managed application.</p>
    pub fn get_idc_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.idc_instance_arn
    }
    /// <p>The name of the Redshift application in IAM Identity Center.</p>
    /// This field is required.
    pub fn redshift_idc_application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.redshift_idc_application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Redshift application in IAM Identity Center.</p>
    pub fn set_redshift_idc_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.redshift_idc_application_name = input;
        self
    }
    /// <p>The name of the Redshift application in IAM Identity Center.</p>
    pub fn get_redshift_idc_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.redshift_idc_application_name
    }
    /// <p>The namespace for the Amazon Redshift IAM Identity Center application instance. It determines which managed application verifies the connection token.</p>
    pub fn identity_namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace for the Amazon Redshift IAM Identity Center application instance. It determines which managed application verifies the connection token.</p>
    pub fn set_identity_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_namespace = input;
        self
    }
    /// <p>The namespace for the Amazon Redshift IAM Identity Center application instance. It determines which managed application verifies the connection token.</p>
    pub fn get_identity_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_namespace
    }
    /// <p>The display name for the Amazon Redshift IAM Identity Center application instance. It appears in the console.</p>
    /// This field is required.
    pub fn idc_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.idc_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name for the Amazon Redshift IAM Identity Center application instance. It appears in the console.</p>
    pub fn set_idc_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.idc_display_name = input;
        self
    }
    /// <p>The display name for the Amazon Redshift IAM Identity Center application instance. It appears in the console.</p>
    pub fn get_idc_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.idc_display_name
    }
    /// <p>The IAM role ARN for the Amazon Redshift IAM Identity Center application instance. It has the required permissions to be assumed and invoke the IDC Identity Center API.</p>
    /// This field is required.
    pub fn iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role ARN for the Amazon Redshift IAM Identity Center application instance. It has the required permissions to be assumed and invoke the IDC Identity Center API.</p>
    pub fn set_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role_arn = input;
        self
    }
    /// <p>The IAM role ARN for the Amazon Redshift IAM Identity Center application instance. It has the required permissions to be assumed and invoke the IDC Identity Center API.</p>
    pub fn get_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role_arn
    }
    /// Appends an item to `authorized_token_issuer_list`.
    ///
    /// To override the contents of this collection use [`set_authorized_token_issuer_list`](Self::set_authorized_token_issuer_list).
    ///
    /// <p>The token issuer list for the Amazon Redshift IAM Identity Center application instance.</p>
    pub fn authorized_token_issuer_list(mut self, input: crate::types::AuthorizedTokenIssuer) -> Self {
        let mut v = self.authorized_token_issuer_list.unwrap_or_default();
        v.push(input);
        self.authorized_token_issuer_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The token issuer list for the Amazon Redshift IAM Identity Center application instance.</p>
    pub fn set_authorized_token_issuer_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AuthorizedTokenIssuer>>) -> Self {
        self.authorized_token_issuer_list = input;
        self
    }
    /// <p>The token issuer list for the Amazon Redshift IAM Identity Center application instance.</p>
    pub fn get_authorized_token_issuer_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AuthorizedTokenIssuer>> {
        &self.authorized_token_issuer_list
    }
    /// Appends an item to `service_integrations`.
    ///
    /// To override the contents of this collection use [`set_service_integrations`](Self::set_service_integrations).
    ///
    /// <p>A collection of service integrations for the Redshift IAM Identity Center application.</p>
    pub fn service_integrations(mut self, input: crate::types::ServiceIntegrationsUnion) -> Self {
        let mut v = self.service_integrations.unwrap_or_default();
        v.push(input);
        self.service_integrations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of service integrations for the Redshift IAM Identity Center application.</p>
    pub fn set_service_integrations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServiceIntegrationsUnion>>) -> Self {
        self.service_integrations = input;
        self
    }
    /// <p>A collection of service integrations for the Redshift IAM Identity Center application.</p>
    pub fn get_service_integrations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServiceIntegrationsUnion>> {
        &self.service_integrations
    }
    /// Consumes the builder and constructs a [`CreateRedshiftIdcApplicationInput`](crate::operation::create_redshift_idc_application::CreateRedshiftIdcApplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_redshift_idc_application::CreateRedshiftIdcApplicationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_redshift_idc_application::CreateRedshiftIdcApplicationInput {
            idc_instance_arn: self.idc_instance_arn,
            redshift_idc_application_name: self.redshift_idc_application_name,
            identity_namespace: self.identity_namespace,
            idc_display_name: self.idc_display_name,
            iam_role_arn: self.iam_role_arn,
            authorized_token_issuer_list: self.authorized_token_issuer_list,
            service_integrations: self.service_integrations,
        })
    }
}
