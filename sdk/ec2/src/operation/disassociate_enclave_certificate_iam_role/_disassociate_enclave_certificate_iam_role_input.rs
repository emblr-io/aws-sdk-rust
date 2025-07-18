// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateEnclaveCertificateIamRoleInput {
    /// <p>The ARN of the ACM certificate from which to disassociate the IAM role.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the IAM role to disassociate.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl DisassociateEnclaveCertificateIamRoleInput {
    /// <p>The ARN of the ACM certificate from which to disassociate the IAM role.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>The ARN of the IAM role to disassociate.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl DisassociateEnclaveCertificateIamRoleInput {
    /// Creates a new builder-style object to manufacture [`DisassociateEnclaveCertificateIamRoleInput`](crate::operation::disassociate_enclave_certificate_iam_role::DisassociateEnclaveCertificateIamRoleInput).
    pub fn builder() -> crate::operation::disassociate_enclave_certificate_iam_role::builders::DisassociateEnclaveCertificateIamRoleInputBuilder {
        crate::operation::disassociate_enclave_certificate_iam_role::builders::DisassociateEnclaveCertificateIamRoleInputBuilder::default()
    }
}

/// A builder for [`DisassociateEnclaveCertificateIamRoleInput`](crate::operation::disassociate_enclave_certificate_iam_role::DisassociateEnclaveCertificateIamRoleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateEnclaveCertificateIamRoleInputBuilder {
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl DisassociateEnclaveCertificateIamRoleInputBuilder {
    /// <p>The ARN of the ACM certificate from which to disassociate the IAM role.</p>
    /// This field is required.
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the ACM certificate from which to disassociate the IAM role.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The ARN of the ACM certificate from which to disassociate the IAM role.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>The ARN of the IAM role to disassociate.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM role to disassociate.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The ARN of the IAM role to disassociate.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
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
    /// Consumes the builder and constructs a [`DisassociateEnclaveCertificateIamRoleInput`](crate::operation::disassociate_enclave_certificate_iam_role::DisassociateEnclaveCertificateIamRoleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_enclave_certificate_iam_role::DisassociateEnclaveCertificateIamRoleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::disassociate_enclave_certificate_iam_role::DisassociateEnclaveCertificateIamRoleInput {
                certificate_arn: self.certificate_arn,
                role_arn: self.role_arn,
                dry_run: self.dry_run,
            },
        )
    }
}
