// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyDefaultCreditSpecificationInput {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>The instance family.</p>
    pub instance_family: ::std::option::Option<crate::types::UnlimitedSupportedInstanceFamily>,
    /// <p>The credit option for CPU usage of the instance family.</p>
    /// <p>Valid Values: <code>standard</code> | <code>unlimited</code></p>
    pub cpu_credits: ::std::option::Option<::std::string::String>,
}
impl ModifyDefaultCreditSpecificationInput {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>The instance family.</p>
    pub fn instance_family(&self) -> ::std::option::Option<&crate::types::UnlimitedSupportedInstanceFamily> {
        self.instance_family.as_ref()
    }
    /// <p>The credit option for CPU usage of the instance family.</p>
    /// <p>Valid Values: <code>standard</code> | <code>unlimited</code></p>
    pub fn cpu_credits(&self) -> ::std::option::Option<&str> {
        self.cpu_credits.as_deref()
    }
}
impl ModifyDefaultCreditSpecificationInput {
    /// Creates a new builder-style object to manufacture [`ModifyDefaultCreditSpecificationInput`](crate::operation::modify_default_credit_specification::ModifyDefaultCreditSpecificationInput).
    pub fn builder() -> crate::operation::modify_default_credit_specification::builders::ModifyDefaultCreditSpecificationInputBuilder {
        crate::operation::modify_default_credit_specification::builders::ModifyDefaultCreditSpecificationInputBuilder::default()
    }
}

/// A builder for [`ModifyDefaultCreditSpecificationInput`](crate::operation::modify_default_credit_specification::ModifyDefaultCreditSpecificationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyDefaultCreditSpecificationInputBuilder {
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) instance_family: ::std::option::Option<crate::types::UnlimitedSupportedInstanceFamily>,
    pub(crate) cpu_credits: ::std::option::Option<::std::string::String>,
}
impl ModifyDefaultCreditSpecificationInputBuilder {
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the operation, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// <p>The instance family.</p>
    /// This field is required.
    pub fn instance_family(mut self, input: crate::types::UnlimitedSupportedInstanceFamily) -> Self {
        self.instance_family = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance family.</p>
    pub fn set_instance_family(mut self, input: ::std::option::Option<crate::types::UnlimitedSupportedInstanceFamily>) -> Self {
        self.instance_family = input;
        self
    }
    /// <p>The instance family.</p>
    pub fn get_instance_family(&self) -> &::std::option::Option<crate::types::UnlimitedSupportedInstanceFamily> {
        &self.instance_family
    }
    /// <p>The credit option for CPU usage of the instance family.</p>
    /// <p>Valid Values: <code>standard</code> | <code>unlimited</code></p>
    /// This field is required.
    pub fn cpu_credits(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cpu_credits = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The credit option for CPU usage of the instance family.</p>
    /// <p>Valid Values: <code>standard</code> | <code>unlimited</code></p>
    pub fn set_cpu_credits(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cpu_credits = input;
        self
    }
    /// <p>The credit option for CPU usage of the instance family.</p>
    /// <p>Valid Values: <code>standard</code> | <code>unlimited</code></p>
    pub fn get_cpu_credits(&self) -> &::std::option::Option<::std::string::String> {
        &self.cpu_credits
    }
    /// Consumes the builder and constructs a [`ModifyDefaultCreditSpecificationInput`](crate::operation::modify_default_credit_specification::ModifyDefaultCreditSpecificationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_default_credit_specification::ModifyDefaultCreditSpecificationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::modify_default_credit_specification::ModifyDefaultCreditSpecificationInput {
                dry_run: self.dry_run,
                instance_family: self.instance_family,
                cpu_credits: self.cpu_credits,
            },
        )
    }
}
